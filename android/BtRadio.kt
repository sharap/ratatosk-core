package org.ratatosk.bt

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import org.ratatosk.core.FfiBluetooth
import org.ratatosk.core.FfiBtRadio
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import kotlin.concurrent.thread

/**
 * Радио для ступени Bluetooth (0.4.7).
 *
 * Половина моста со стороны платформы. Всё, что здесь есть, — вещать,
 * слушать и переносить байты; ни формата объявления, ни опознания
 * контактов, ни кадрирования тут нет и быть не должно — они живут
 * в ядре, одним экземпляром на оба радио.
 *
 * **Ни один метод не ждёт исхода.** `connect` блокирует поток на секунды,
 * запись в `OutputStream` — на время передачи, а вызов из ядра синхронный.
 * Поэтому здесь всё уезжает в свои потоки, а об исходе ядру сообщает
 * событие на [bridge].
 *
 * Живёт в службе переднего плана: сканирование и объявление идут всё
 * время, пока ступень включена, и обычная `Activity` этого не переживёт.
 */
class BtRadio(
    private val context: Context,
    private val bridge: FfiBluetooth,
) : FfiBtRadio {

    private companion object {
        const val TAG = "ratatosk.bt"

        /** Код производителя объявления. Тот же, что собирает ядро. */
        const val COMPANY_ID = 0xFFFF

        /** Длина нашей нагрузки: запись маяка 16 плюс номер канала 2. */
        const val PAYLOAD_LEN = 18

        /** Сколько читать за раз. Кусок произвольный — режет кадры ядро. */
        const val READ_CHUNK = 4096
    }

    /**
     * Разрешения, без которых радио не поднимется.
     *
     * Вынесено из класса наружу: спрашивать их обязано приложение, и
     * обязано **до** `setRadio`. Розданное без разрешений радио уходит
     * в `onLost` с текстом «нет разрешений», и человек видит сломанную
     * ступень вместо запроса.
     */
    object Permissions {
        fun required(): List<String> =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                listOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_CONNECT,
                )
            } else {
                // API 29–30: разрешений на сам Bluetooth не спрашивают
                // (`BLUETOOTH` и `BLUETOOTH_ADMIN` выдаются при установке),
                // а вот обзор BLE требует **геолокации** — и именно точной.
                listOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }

        fun missing(context: Context): List<String> = required().filter {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }
    }

    private val adapter: BluetoothAdapter? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager?)?.adapter

    /** Открытые каналы: и набранные нами, и принятые. */
    private val channels = ConcurrentHashMap<Long, Channel>()

    /**
     * Устройства, которые мы сами услышали в эфире, по адресу.
     *
     * **Ради этой карты набор и устроен так, как устроен.** Объект
     * `BluetoothDevice`, пришедший из обзора, уже знает вид своего адреса —
     * система сопоставила его сама. Собирать такой же объект по адресу
     * и виду (`getRemoteLeDevice`) значит повторять её работу и заодно
     * зависеть от уровня API, на котором этот способ появился.
     *
     * А услышали мы его обязательно: ядро набирает **только** тех, чьё
     * объявление опознало, — то есть карта заполнена раньше, чем придёт
     * приказ набирать. Способ по адресу остаётся запасным и почти
     * не работает.
     */
    private val seen = ConcurrentHashMap<String, BluetoothDevice>()

    /** Слушающий сокет. Его номер уезжает в объявление. */
    @Volatile private var server: BluetoothServerSocket? = null

    @Volatile private var advertising: AdvertiseCallback? = null
    @Volatile private var scanning: ScanCallback? = null

    /**
     * Набор — на своих потоках, по одному на канал.
     *
     * `connect` блокирует, и пул тут не годится: десяток одновременных
     * наборов занял бы весь пул, а одиннадцатый ждал бы, не начавшись.
     */
    private val dialers = Executors.newCachedThreadPool()

    /**
     * Поток, с которого мы говорим ядру. Один и тот же на все события.
     *
     * **Отвечать ядру прямо из его же вызова нельзя.** Методы `FfiBtRadio`
     * зовутся с потока Rust, который JNA присоединяет к JVM на время
     * вызова. Обращение к `bridge` оттуда уходит обратно в нативный код,
     * и на возврате ART отцепляет поток, пока на нём ещё лежат кадры Java:
     *
     *     Thread[...] attempting to detach while still running code
     *
     * Это не исключение, а abort — приложение просто исчезает. Так оно
     * и падало при первом же включении ступени: `start()` отвечал
     * `onReady` немедленно.
     *
     * Поток один, а не пул: порядок событий значим. `onReady` обязан
     * дойти раньше первого `onHeard`, а куски канала — прийти подряд.
     */
    private val notifier = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "ratatosk-bt-notify")
    }

    /** Сказать ядру — всегда через [notifier], никогда напрямую. */
    private fun toCore(what: String, block: () -> Unit) {
        notifier.execute {
            try {
                block()
            } catch (t: Throwable) {
                Log.e(TAG, "ядру не сказали про $what: ${t.message}", t)
            }
        }
    }

    // ---- вниз: то, что зовёт ядро -------------------------------------

    override fun start() {
        val adapter = this.adapter
        if (adapter == null || !adapter.isEnabled) {
            // Адаптер мы не включаем: выключенный Bluetooth — выбор
            // человека, и щёлкать его переключатель за него нельзя.
            toCore("onLost") { bridge.onLost("Bluetooth выключен") }
            return
        }
        val missing = missingPermissions()
        if (missing.isNotEmpty()) {
            // Словами, а не тишиной: «включено и не работает» без причины
            // выглядит как поломка.
            toCore("onLost") { bridge.onLost("нет разрешений: ${missing.joinToString(", ")}") }
            return
        }

        try {
            // Небезопасный канал — то есть без требования пары.
            // Пара нам не нужна: личность даёт рукопожатие (§8.2),
            // а не сопряжение устройств, и требовать её значило бы
            // просить человека сопрягать телефоны ради переписки.
            val socket = adapter.listenUsingInsecureL2capChannel()
            server = socket
            thread(name = "ratatosk-bt-accept") { acceptLoop(socket) }
            startScan(adapter)
            // Номер канала — последним: объявление ядро соберёт по нему.
            toCore("onReady") { bridge.onReady(socket.psm.toUShort()) }
        } catch (e: Throwable) {
            Log.w(TAG, "эфир не поднялся", e)
            stop()
            toCore("onLost") { bridge.onLost(e.message ?: "сокет L2CAP не открылся") }
        }
    }

    override fun advertise(payload: ByteArray) {
        val adapter = this.adapter ?: return
        val advertiser = adapter.bluetoothLeAdvertiser ?: run {
            toCore("onLost") { bridge.onLost("устройство не умеет объявляться") }
            return
        }
        if (payload.size != PAYLOAD_LEN) {
            // Длина нагрузки — она же и номер версии формата (0.4.3).
            // Другая длина означает, что ядро и это радио из разных сборок.
            Log.w(TAG, "нагрузка не нашей длины: ${payload.size}")
            return
        }

        // Прежнее снимается перед новым: два объявления одного радио
        // в эфире — подсказка тому, кто их сличает.
        advertising?.let { advertiser.stopAdvertising(it) }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            // **Подключаемое.** Иначе нас видно, а подойти нельзя.
            .setConnectable(true)
            .setTimeout(0)
            .build()
        val data = AdvertiseData.Builder()
            // **Имя выключается руками.** Иначе система добавит его сама,
            // а имена телефонов длиннее нашего запаса в шесть байт —
            // объявления не будет вовсе. И оно вещало бы имя телефона.
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addManufacturerData(COMPANY_ID, payload)
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartFailure(errorCode: Int) {
                Log.w(TAG, "объявление не пошло: $errorCode")
                toCore("onLost") { bridge.onLost("объявление отвергнуто системой ($errorCode)") }
            }
        }
        advertising = callback
        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (e: SecurityException) {
            toCore("onLost") { bridge.onLost("нет разрешения на объявление") }
        }
    }

    override fun stop() {
        val adapter = this.adapter
        advertising?.let { callback ->
            advertising = null
            runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(callback) }
        }
        scanning?.let { callback ->
            scanning = null
            runCatching { adapter?.bluetoothLeScanner?.stopScan(callback) }
        }
        runCatching { server?.close() }
        server = null
        // Каналы закрываются все: после включения они будут другими.
        channels.keys.toList().forEach { closeLong(it) }
        // И услышанное забывается вместе с эфиром: адрес BLE ротируется,
        // и устройство, запомненное четверть часа назад, — не то же самое.
        seen.clear()
    }

    /**
     * `random` здесь не используется, и это осознанно: набор идёт
     * запомненным объектом устройства, который вид своего адреса знает
     * сам (см. [seen]). Из договора вид не убран потому, что на Linux
     * набирают по адресу, и там он обязателен.
     */
    override fun open(channel: ULong, address: ByteArray, random: Boolean, psm: UShort) {
        val adapter = this.adapter
        if (adapter == null) {
            toCore("onOpenFailed") { bridge.onOpenFailed(channel, "адаптера нет") }
            return
        }
        dialers.execute {
            try {
                val text = hex(address)
                // Тот самый объект, который пришёл из обзора: он уже знает
                // вид своего адреса. Запасной способ — по строке; он годится
                // только для публичного адреса, и потому именно запасной.
                val device = seen[text] ?: adapter.getRemoteDevice(text)
                val socket = device.createInsecureL2capChannel(psm.toInt())
                // Обзор на время набора останавливать обязательно:
                // сканирование и соединение делят одно радио, и с
                // включённым обзором `connect` заметно чаще не удаётся.
                runCatching { adapter.bluetoothLeScanner?.stopScan(scanning) }
                socket.connect()
                register(channel, socket)
                toCore("onOpened") { bridge.onOpened(channel) }
                startScan(adapter)
            } catch (e: Throwable) {
                Log.w(TAG, "канал не открылся", e)
                runCatching { startScan(adapter) }
                toCore("onOpenFailed") { bridge.onOpenFailed(channel, e.message ?: "connect не удался") }
            }
        }
    }

    override fun write(channel: ULong, bytes: ByteArray) {
        val held = channels[channel.toLong()]
        if (held == null) {
            // Ядро пишет в канал, которого у нас нет. Сказать об этом
            // обязательно: молчание здесь превращается в «отправляется»
            // на мёртвом канале.
            toCore("onClosed") { bridge.onClosed(channel) }
            return
        }
        // Очередь, а не запись здесь: этот вызов обязан не ждать.
        held.outgoing.put(bytes)
    }

    override fun close(channel: ULong) {
        closeLong(channel.toLong())
    }

    // ---- вверх и вбок: своё хозяйство ---------------------------------

    private fun acceptLoop(socket: BluetoothServerSocket) {
        while (true) {
            val accepted = try {
                socket.accept()
            } catch (e: IOException) {
                // Сокет закрыли — значит ступень выключили. Это не беда.
                return
            }
            val channel = nextChannel()
            register(channel.toULong(), accepted)
            toCore("onIncoming") { bridge.onIncoming(channel.toULong()) }
        }
    }

    /**
     * Номера принятых каналов.
     *
     * Набранным номера даёт ядро, а принятым — мы, и пересечься они
     * не должны. Поэтому свои идут сверху вниз: ядро считает снизу вверх,
     * и встретятся они не раньше, чем через девять квинтиллионов каналов.
     */
    private var incomingCounter = Long.MAX_VALUE

    @Synchronized private fun nextChannel(): Long = incomingCounter--

    private fun register(channel: ULong, socket: BluetoothSocket) {
        val held = Channel(socket)
        channels[channel.toLong()] = held
        thread(name = "ratatosk-bt-read-$channel") { readLoop(channel, held.input) }
        thread(name = "ratatosk-bt-write-$channel") { writeLoop(channel, held) }
    }

    private fun readLoop(channel: ULong, input: InputStream) {
        val buffer = ByteArray(READ_CHUNK)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                // Кусок отдаётся как есть. Резать его по кадрам нельзя:
                // где кончается кадр, знает кадрирование в ядре.
                toCore("onBytes") { bridge.onBytes(channel, buffer.copyOf(read)) }
            }
        } catch (e: IOException) {
            // Обычный конец канала: собеседник ушёл или эфир пропал.
        }
        closeLong(channel.toLong())
    }

    private fun writeLoop(channel: ULong, held: Channel) {
        try {
            while (true) {
                val bytes = held.outgoing.take()
                if (bytes.isEmpty()) break
                held.output.write(bytes)
                // Сброс на каждую запись: кадр записан значит кадр
                // отправлен — то же правило, что в ядре.
                held.output.flush()
            }
        } catch (e: Throwable) {
            // Запись не прошла — канал мёртв, и ядро обязано узнать.
        }
        closeLong(channel.toLong())
    }

    private fun closeLong(channel: Long) {
        val held = channels.remove(channel) ?: return
        // Пустой кусок будит пишущий поток, стоящий на `take`.
        held.outgoing.offer(ByteArray(0))
        runCatching { held.socket.close() }
        toCore("onClosed") { bridge.onClosed(channel.toULong()) }
    }

    private fun startScan(adapter: BluetoothAdapter) {
        val scanner = adapter.bluetoothLeScanner ?: return
        scanning?.let { runCatching { scanner.stopScan(it) } }

        // Фильтр по коду производителя — не ради приватности, а ради
        // батареи: в вагоне метро под BLE вещает всякий наушник, и
        // будить приложение на каждого из них незачем.
        val filter = ScanFilter.Builder()
            .setManufacturerData(COMPANY_ID, ByteArray(0), ByteArray(0))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            // Повторы нужны: собеседник переобъявляется со сменой слота,
            // и без повторов мы узнали бы об этом только при следующем
            // его появлении в эфире.
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setReportDelay(0)
            .build()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val payload = result.scanRecord
                    ?.getManufacturerSpecificData(COMPANY_ID)
                    ?: return
                if (payload.size != PAYLOAD_LEN) return
                val address = parseAddress(result.device.address) ?: return
                // Само устройство запоминается: набирать мы будем **им**,
                // а не собранным по адресу. См. `seen`.
                seen[result.device.address] = result.device
                // Вид адреса здесь всегда «случайный», и это не догадка,
                // а следствие: на Android мы его не спрашиваем вовсе —
                // набор идёт запомненным устройством. Значение живёт
                // в справочнике ядра (адреса сравниваются целиком, и вид
                // обязан быть одинаков у объявления и у набора) и до радио
                // возвращается неиспользованным. На Linux, где набор идёт
                // по адресу, вид определяется по-настоящему.
                toCore("onHeard") { bridge.onHeard(payload, address, true) }
            }

            override fun onScanFailed(errorCode: Int) {
                Log.w(TAG, "обзор не пошёл: $errorCode")
            }
        }
        scanning = callback
        try {
            scanner.startScan(listOf(filter), settings, callback)
        } catch (e: SecurityException) {
            toCore("onLost") { bridge.onLost("нет разрешения на обзор") }
        }
    }

    private fun missingPermissions(): List<String> = Permissions.missing(context)

    /** `AA:BB:CC:DD:EE:FF` — в том виде, в каком адрес ждёт Android. */
    private fun hex(address: ByteArray): String =
        address.joinToString(":") { "%02X".format(it) }

    /** И обратно: шесть байт из строки, которую даёт `ScanResult`. */
    private fun parseAddress(text: String): ByteArray? {
        val parts = text.split(":")
        if (parts.size != 6) return null
        return runCatching {
            ByteArray(6) { parts[it].toInt(16).toByte() }
        }.getOrNull()
    }

    /** Один канал: сокет, его потоки и очередь на запись. */
    private class Channel(val socket: BluetoothSocket) {
        val input: InputStream = socket.inputStream
        val output: OutputStream = socket.outputStream
        val outgoing = LinkedBlockingQueue<ByteArray>()
    }
}
