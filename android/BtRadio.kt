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

        /** Через сколько принятых байт говорить об этом в журнале. */
        const val COUNT_STEP = 64L * 1024


        /**
         * Насколько глубже прежнего должна стать очередь к ядру, чтобы
         * об этом написать. Шестнадцать: кадр класса M приходит восемью
         * чтениями, то есть ступенька — это два отставших кадра.
         */
        const val DEPTH_STEP = 16

        /** Начальное значение FNV-1a, 64 бита. То же, что в ядре. */
        const val FNV_OFFSET = -3750763034362895579L

        /** Множитель FNV-1a, 64 бита. */
        const val FNV_PRIME = 1099511628211L

        /**
         * Сколько ждать между запусками обзора.
         *
         * **Android считает запуски и молча наказывает за частые.**
         * Ограничение — пять `startScan` за тридцать секунд на приложение;
         * шестой не отвергается с ошибкой, а принимается и не приносит
         * ни одного объявления. Снаружи это выглядит как «блютуз устал»:
         * связь есть, а собеседников больше не видно, и починить это можно
         * только перезапуском ступени.
         *
         * Набор останавливает обзор и поднимает его снова, то есть на каждый
         * набор приходится один запуск. Шесть секунд между запусками
         * оставляют пять штук на тридцать секунд ровно — с запасом в ноль,
         * зато честным.
         */
        const val SCAN_COOLDOWN_MS = 6_000L

        /** Через сколько поднимать обзор после набора. */
        const val SCAN_RESUME_MS = 1_500L
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
     *
     * # Очередь безграничная, и это **не недосмотр**
     *
     * Здесь стояла ограниченная очередь, сдача в которую ждала места.
     * Замысел был хорош: ждёт поток чтения, пока он ждёт — сокет
     * не вычитывается, кредиты L2CAP не возвращаются, запись
     * у отправителя стоит. Управление потоком, ради которого L2CAP его
     * и имеет, начинает работать.
     *
     * На стенде вышло наоборот: замер `m` до правки доходил до семидесяти
     * кадров, после — до пятнадцати-двадцати. Порча пошла **чаще**.
     *
     * Причина в том, что буфер за сокетом не наш. Пока поток чтения стоит,
     * принятое копится в приёмном буфере `BluetoothSocket`, а он
     * фиксированного размера и не обязан ни ждать, ни отказывать:
     * переполнившись, он отдаёт нам столько же байт, сколько было послано, но часть из них
     * уже не та. Снаружи это ровно тот почерк, что мы ловим: `всего`
     * сходится до байта, кадрирование не сбито, длина верна — а тег AEAD
     * не сходится.
     *
     * Отсюда правило: **поток чтения не останавливается никогда.** Буфер,
     * который нам не принадлежит, обязан вычитываться немедленно; копить
     * можно только у себя, где переполнение видно и честно кончается
     * обрывом, а не подменой байт.
     *
     * Цена — память: при отставшем ядре очередь растёт со скоростью эфира,
     * то есть десятками килобайт в секунду. Ограничена она сроком ожидания
     * в мосту (`ROOM_LIMIT`): полминуты отставания — и канал закрывается
     * честно. Больше мебибайта здесь не накопится.
     */
    private val notifier = java.util.concurrent.ThreadPoolExecutor(
        1,
        1,
        0L,
        java.util.concurrent.TimeUnit.MILLISECONDS,
        java.util.concurrent.LinkedBlockingQueue<Runnable>(),
        java.util.concurrent.ThreadFactory { runnable ->
            Thread(runnable, "ratatosk-bt-notify")
        },
    )

    /**
     * Отложенные дела радио: поднять обзор после набора и не чаще, чем можно.
     *
     * Своим потоком, а не на [notifier]: тот разговаривает с ядром, и ждать
     * на нём полторы секунды значило бы задержать все кадры канала.
     */
    private val timer = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "ratatosk-bt-timer")
    }

    /** Когда обзор запускали в последний раз. */
    @Volatile private var scanStarted = 0L

    /** Самая глубокая очередь к ядру, какую видели. Только для журнала. */
    @Volatile private var deepest = 0

    /** Ждёт ли уже отложенный подъём обзора. */
    private val scanPending = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Сказать ядру — всегда через [notifier], никогда напрямую.
     *
     * Сдача не ждёт и не отказывает: очередь безграничная (см. [notifier]),
     * и поток, принёсший дело, уходит немедленно. Для потока чтения канала
     * это обязательно — остановись он, переполнился бы приёмный буфер
     * сокета, который нам не принадлежит.
     */
    private fun toCore(what: String, block: () -> Unit) {
        noteDepth()
        notifier.execute {
            try {
                block()
            } catch (t: Throwable) {
                Log.e(TAG, "ядру не сказали про $what: ${t.message}", t)
            }
        }
    }

    /**
     * Самая глубокая очередь к ядру за всё время — в журнал, по ступенькам.
     *
     * **Единственный способ узнать, отстаёт ли ядро вообще.** Очередь
     * безграничная, и отставание в ней больше никак не проявляется: канал
     * не рвётся, кадры не теряются, просто растёт память. А вопрос стоит
     * ребром — порча байт приходит от переполнения где-то ниже или сверху,
     * — и без этой цифры он решается гаданием.
     *
     * По ступенькам, а не на каждое дело: строка на кусок утопила бы
     * журнал, а интересна тут одна величина — наибольшая.
     */
    /**
     * Размеры чтений — сжато, подряд идущие одинаковые одной записью.
     *
     * **Это то место, где разбор упёрся в стену, и вот почему цифра нужна
     * именно такая.** Кадр класса `M` между двумя стендами проходит сто
     * раз из ста, а к телефону — пятнадцать-двадцать пять. Отправитель,
     * эфир и кадрирование чисты; значит порча живёт здесь, между сокетом
     * и нашим буфером. Чем именно платформа режет поток — единственное,
     * чего мы про это место не знаем.
     *
     * Одна цифра `последний` этого не показывала: она называла размер
     * одного чтения из пары сотен. Нужен весь набор, и он же должен
     * отличать испорченный кадр от целого — если отличает.
     *
     * Сжатие обязательно: без него на кадр выходит десять строк, а
     * на прогон — тысяча.
     */
    private fun runs(sizes: List<Int>): String {
        if (sizes.isEmpty()) return "—"
        val out = StringBuilder()
        var head = sizes[0]
        var many = 1
        for (size in sizes.drop(1)) {
            if (size == head) {
                many++
                continue
            }
            if (out.isNotEmpty()) out.append(',')
            out.append(if (many > 1) "$head×$many" else "$head")
            head = size
            many = 1
        }
        if (out.isNotEmpty()) out.append(',')
        out.append(if (many > 1) "$head×$many" else "$head")
        return out.toString()
    }

    private fun noteDepth() {
        val depth = notifier.queue.size
        if (depth < deepest + DEPTH_STEP) return
        deepest = depth
        Log.i(TAG, "очередь к ядру: в ней $depth дел — ядро отстаёт")
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
        // Отложенный подъём обзора отменяется вместе со ступенью: иначе он
        // сработает через секунду после того, как человек выключил эфир.
        scanPending.set(false)
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
                // **Не встык к соединению.** Канал только что открылся,
                // и первые кадры по нему идут прямо сейчас; обзор, поднятый
                // в эту секунду, отберёт у них антенну. Полторы секунды
                // роли не играют: объявления собеседника повторяются.
                timer.schedule(
                    { startScan(adapter) },
                    SCAN_RESUME_MS,
                    java.util.concurrent.TimeUnit.MILLISECONDS,
                )
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
        thread(name = "ratatosk-bt-read-$channel") { readLoop(channel, held) }
        thread(name = "ratatosk-bt-write-$channel") { writeLoop(channel, held) }
    }

    private fun readLoop(channel: ULong, held: Channel) {
        val input = held.input
        // **Размер буфера спрашивается у сокета, а не берётся из головы.**
        //
        // `BluetoothSocket` поверх L2CAP отдаёт за одно чтение **пакет**,
        // и буфер меньше пакета означает, что хвост пакета пропадёт молча.
        // Документация Android прямо велит брать размер отсюда и называет
        // это оптимизацией чтения; на самом деле это условие правильности.
        //
        // Поломка от этого выглядит обманчиво целой: кадр собирается
        // нужной длины — недостающее `read_exact` доберёт из следующих
        // байт, — заголовок в начале цел, а середина сдвинута, и тег AEAD
        // не сходится. Мелкие кадры при этом ходят: их пакеты меньше.
        val packet = runCatching { held.socket.maxReceivePacketSize }.getOrDefault(0)
        val buffer = ByteArray(maxOf(READ_CHUNK, packet))
        Log.i(TAG, "чтение канала $channel: буфер ${buffer.size}, пакет $packet")

        // **Отпечаток всего, что мы прочитали из сокета.**
        //
        // Последняя развилка разбора. Кадр доезжает до ядра нужной длины,
        // кадрирование не сбивается, а тег AEAD не сходится — значит байты
        // заменяются на месте. Заменить их может либо провод (мы прочитали
        // не то), либо дорога отсюда к ядру (копия, очередь, граница FFI).
        //
        // Ту же цифру по тем же байтам считает мост (`bluetooth::bridge`,
        // поле `поток`). Сошлись — виноват провод; разошлись — дорога,
        // и искать надо здесь.
        var rolling = FNV_OFFSET
        var counted = 0L
        var said = 0L
        // Размеры всех чтений с прошлой строки журнала. Разбор — у [runs].
        val sizes = ArrayList<Int>()
        try {
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                // **Копия снимается здесь, а не внутри `toCore`.**
                //
                // Стояло `toCore("onBytes") { bridge.onBytes(channel, buffer.copyOf(read)) }`,
                // и это была гонка. Тело `toCore` выполняется **потом**,
                // на потоке `notifier`, а `buffer` — один на весь цикл:
                // пока копия ждала своей очереди, следующий `input.read`
                // уже переписывал её содержимое. В ядро уезжали не те
                // байты, что пришли из сокета.
                //
                // Почему вылезло только на файлах. Мелкий кадр приходит
                // одним-двумя чтениями, между которыми сокет пуст и поток
                // стоит — очередь успевает разойтись, и копия снимается
                // с нетронутого буфера. Мебибайт приходит сотнями чтений
                // подряд: буфер переписывается быстрее, чем `notifier`
                // доходит до копии.
                //
                // Снаружи это выглядело так: кадр класса L доезжал целиком
                // и **правильной длины** — длину-то каждая копия давала
                // верную, — а ядро отвергало его как «неподдерживаемая
                // версия кадра: 100». Мелкие кадры при этом ходили годами.
                //
                // Кусок отдаётся как есть. Резать его по кадрам нельзя:
                // где кончается кадр, знает кадрирование в ядре.
                val chunk = buffer.copyOf(read)
                // Считается по **копии**, а не по буферу: сличать надо
                // ровно те байты, что уедут в ядро.
                rolling = fnvUpdate(rolling, chunk)
                counted += read
                sizes.add(read)
                val step = counted / COUNT_STEP
                if (step != said) {
                    said = step
                    Log.d(
                        TAG,
                        "чтение канала $channel: всего=$counted куски=${runs(sizes)} " +
                            "поток=${"%016x".format(rolling)}",
                    )
                    sizes.clear()
                }
                toCore("onBytes") { bridge.onBytes(channel, chunk) }
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
        // Разговоров больше нет — антенна свободна, и обзору незачем сидеть
        // на экономном режиме. Запуск при этом всё равно проходит через
        // квоту: закрытий бывает много подряд.
        if (channels.isEmpty()) {
            adapter?.let { startScan(it) }
        }
    }

    /**
     * Поднимает обзор — не чаще, чем Android разрешает.
     *
     * **Запуски обзора считаются системой.** Пять `startScan` за тридцать
     * секунд на приложение; шестой принимается молча и не приносит
     * ни одного объявления. Набор останавливает обзор и поднимает снова,
     * то есть на десяток наборов подряд приходится десяток запусков —
     * и после пятого телефон перестаёт кого-либо видеть. Снаружи это
     * и есть «блютуз устал»: связь работает, а собеседники пропали.
     *
     * Поэтому запуск откладывается, если прошлый был недавно, и ставится
     * в очередь один раз: [scanPending] не даёт набрать хвост из отложенных
     * подъёмов, каждый из которых съел бы свою квоту.
     */
    private fun startScan(adapter: BluetoothAdapter) {
        // Ступень могли выключить, пока подъём ждал своей очереди. Поднимать
        // обзор после `stop()` — это молча вернуть человека в эфир, чего он
        // как раз и не просил.
        if (server == null) {
            return
        }
        val waited = System.currentTimeMillis() - scanStarted
        if (waited < SCAN_COOLDOWN_MS) {
            if (scanPending.compareAndSet(false, true)) {
                val delay = SCAN_COOLDOWN_MS - waited
                Log.i(TAG, "обзор придержан на $delay мс: квота Android")
                timer.schedule(
                    {
                        scanPending.set(false)
                        startScan(adapter)
                    },
                    delay,
                    java.util.concurrent.TimeUnit.MILLISECONDS,
                )
            }
            return
        }
        val scanner = adapter.bluetoothLeScanner ?: return
        scanning?.let { runCatching { scanner.stopScan(it) } }

        // Фильтр по коду производителя — не ради приватности, а ради
        // батареи: в вагоне метро под BLE вещает всякий наушник, и
        // будить приложение на каждого из них незачем.
        val filter = ScanFilter.Builder()
            .setManufacturerData(COMPANY_ID, ByteArray(0), ByteArray(0))
            .build()
        // **Режим зависит от того, занято ли радио.** Обзор и канал делят
        // одну антенну: пока канал открыт, обзор отбирает у него время,
        // и чем выше скважность обзора, тем медленнее идут кадры. На Linux
        // это решено уступкой антенны на время набора (`Airtime`), здесь —
        // режимом: пока разговор идёт, обзор переходит на экономный.
        val busy = channels.isNotEmpty()
        val mode = if (busy) {
            ScanSettings.SCAN_MODE_LOW_POWER
        } else {
            ScanSettings.SCAN_MODE_BALANCED
        }
        val settings = ScanSettings.Builder()
            .setScanMode(mode)
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
                // **Причина называется словом, а не числом.** Разбор
                // «телефон никого не видит» начинался с гадания, что
                // означает цифра; чаще всего это оказывалась квота.
                val why = when (errorCode) {
                    SCAN_FAILED_ALREADY_STARTED -> "обзор уже идёт"
                    SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "система не дала места"
                    SCAN_FAILED_FEATURE_UNSUPPORTED -> "устройство так не умеет"
                    SCAN_FAILED_INTERNAL_ERROR -> "внутренняя ошибка стека"
                    else -> "код $errorCode (5 — слишком частые запуски)"
                }
                Log.w(TAG, "обзор не пошёл: $why")
            }
        }
        scanning = callback
        try {
            scanner.startScan(listOf(filter), settings, callback)
            scanStarted = System.currentTimeMillis()
            Log.i(TAG, "обзор пошёл: режим ${if (busy) "экономный" else "обычный"}")
        } catch (e: SecurityException) {
            toCore("onLost") { bridge.onLost("нет разрешения на обзор") }
        }
    }

    private fun missingPermissions(): List<String> = Permissions.missing(context)

    /**
     * Продолжает отпечаток потока на следующих байтах.
     *
     * FNV-1a, 64 бита — тот же, что считает ядро (`link::fnv_update`).
     * Байт берётся беззнаковым: в Kotlin `Byte` знаковый, и без маски
     * цифры разошлись бы на первом же байте старше `0x7f` — то есть
     * сравнение, ради которого всё это и заведено, врало бы всегда.
     */
    private fun fnvUpdate(start: Long, bytes: ByteArray): Long {
        var hash = start
        for (b in bytes) {
            hash = hash xor (b.toLong() and 0xff)
            hash *= FNV_PRIME
        }
        return hash
    }

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
