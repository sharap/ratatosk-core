//! Байты файлов — вне SQLite (§10, §12).
//!
//! В базе лежат **метаданные**: имя, размер, ключ, какие чанки приняты.
//! Сами байты живут отдельно, и это не деталь реализации. Двухгигабайтное
//! вложение в BLOB-столбце означает переписывание страницы SQLite на каждый
//! чанк, WAL размером с файл и невозможность отдать содержимое системе,
//! не вынув его целиком в память.
//!
//! # Что здесь есть и чего нет
//!
//! Здесь есть чтение и запись байтов. Здесь **нет криптографии**: чанк
//! приходит уже запечатанным и в таком виде и ложится на диск, а расшифровка
//! живёт в ядре (§8.1 — комбинирование примитивов в одном модуле). Слой
//! получается тупым, и это его достоинство: подменить его на память для
//! симуляции (§16) можно без единой мысли о ключах.
//!
//! # Принятые чанки хранятся запечатанными
//!
//! Так они и приехали. Отсюда три следствия, ради которых это и сделано:
//! содержимое вложения на диске защищено тем же ключом, что и переписка
//! в базе (потерянный телефон не отдаёт фотографии); возобновление (§10.2)
//! не требует ничего, кроме списка присутствующих чанков; а проверка
//! целостности (§10.1) делается по тем же байтам, что лежат на диске, —
//! тегом AEAD каждого чанка.
//!
//! Плата — расшифровка при каждом открытии файла. Для картинки в чате это
//! незаметно, для видео это одна операция на просмотр; альтернатива —
//! открытый файл рядом с зашифрованной базой — сводит §12 к декорации.
//!
//! # Сборку файла делает клиент, а не ядро
//!
//! Здесь нет метода «собери файл по пути». Расшифрованные чанки ядро отдаёт
//! наружу по одному (`RatatoskClient::open_file`), а куда их сложить — в
//! галерею, в загрузки, в облако — решает клиент, и только он это и умеет:
//! на Android запись в общую память идёт через системные интерфейсы, которых
//! у ядра нет и быть не должно. Заодно ядро не берётся за работу порядка
//! размера файла в одном шаге.
//!
//! # Порядок записи и отметки
//!
//! Чанк сперва ложится на диск, и **только потом** отмечается принятым
//! в базе. Обратный порядок означал бы, что после падения процесса файл
//! считается собранным из куска, которого нет. Незамеченный чанк, наоборот,
//! стоит одной повторной передачи — его просто попросят снова.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::{Result, StoreError};

/// Идентификатор файла (§10.1).
pub type FileId = [u8; 16];

/// Чтение байтов — и только оно.
///
/// Отдельно от [`Blobs`], потому что у чтения другое место в программе.
/// Хранилищем владеет ядро, и всё, что делается через него, делается
/// в цикле ядра, по одному действию за раз. Для записи это правильно:
/// принятый чанк надо и записать, и отметить в базе, и порядок этих
/// операций — часть протокола.
///
/// А чтение вложения ничего в состоянии не меняет и ждать своей очереди
/// не обязано. Раньше обязано было: клиент забирал файл кусок за куском
/// через ядро, каждый кусок — заход в общую очередь, и мебибайт расшифровки
/// заодно останавливал отправку сообщений. Отдельный доступ на чтение — это
/// и есть право уйти из очереди.
///
/// `Send + Sync` в возвращаемом типе не украшение: смысл в том, чтобы читать
/// **из другого потока**, пока ядро занято своим.
pub trait ChunkSource {
    /// Читает кусок файла по пути — исходника, который отправляем.
    ///
    /// # Errors
    ///
    /// Отказ диска. Файла может не быть: исходник живёт своей жизнью.
    fn read_at(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>>;

    /// Читает принятый чанк как он лежит — запечатанным. `None` — его нет.
    ///
    /// # Errors
    ///
    /// Отказ диска.
    fn chunk(&self, file_id: &FileId, index: u64) -> Result<Option<Vec<u8>>>;
}

/// Хранилище байтов файлов.
///
/// Трейт, а не тип, ровно по той же причине, что и [`crate::Store`]: без
/// второй реализации абстракция не бывает честной, а симуляция (§16) не должна
/// трогать диск.
pub trait Blobs: ChunkSource {
    /// Размер исходного файла — того, который пользователь просит отправить.
    fn size_of(&self, path: &Path) -> Result<u64>;

    /// Кладёт принятый чанк — **запечатанным, как приехал**.
    fn put_chunk(&mut self, file_id: &FileId, index: u64, sealed: &[u8]) -> Result<()>;

    /// Убирает все чанки файла: передача отменена, сообщение удалено,
    /// вложение вычищено уборкой (§12).
    fn remove(&mut self, file_id: &FileId) -> Result<()>;

    /// Убирает один чанк.
    ///
    /// Нужен уборке: чанк, записанный на диск, но не отмеченный в базе
    /// (процесс умер между двумя операциями), не читается никогда — его
    /// просто попросят снова и перезапишут. До уборки он лежал вечно.
    fn remove_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()>;

    /// Чьи чанки лежат на диске.
    ///
    /// Это половина ответа на вопрос «что тут лишнее»; вторую половину —
    /// что числится в базе — знает [`crate::Store::all_file_ids`]. Сверять
    /// их обязан тот, у кого есть оба, то есть ядро.
    fn stored_files(&self) -> Result<Vec<FileId>>;

    /// Какие чанки файла лежат на диске: номер и размер в байтах.
    ///
    /// Размер здесь не любопытство: человеку, который жмёт «освободить
    /// место», надо сказать сколько освободилось, а после удаления считать
    /// уже нечего.
    fn stored_chunks(&self, file_id: &FileId) -> Result<Vec<(u64, u64)>>;

    /// Второй доступ к тем же байтам — для чтения в стороне от ядра.
    ///
    /// Зачем это нужно, написано у [`ChunkSource`]. Здесь важно другое: это
    /// **тот же** набор байтов, а не копия. У [`FsBlobs`] доступ к диску
    /// вообще не состояние — только путь, — поэтому второй доступ ничего
    /// не стоит и ничему не мешает.
    fn reader(&self) -> Box<dyn ChunkSource + Send + Sync>;
}

/// Байты на настоящем диске.
///
/// Раскладка: `<root>/<file_id в hex>/<номер чанка>`. Один файл на чанк, и это
/// осознанно — так «какие чанки уже есть» отвечает файловая система, а не
/// отдельный учёт, который может разойтись с содержимым каталога. Для файла
/// предельного размера это две тысячи записей в каталоге: много для `ls`,
/// пустяк для файловой системы.
#[derive(Debug, Clone)]
pub struct FsBlobs {
    root: PathBuf,
}

impl FsBlobs {
    /// Хранилище в каталоге. Каталог создаётся при первой записи.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> FsBlobs {
        FsBlobs { root: root.into() }
    }

    /// Каталог, в котором лежат чанки.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir_of(&self, file_id: &FileId) -> PathBuf {
        use std::fmt::Write as _;

        let mut name = String::with_capacity(32);
        for byte in file_id {
            let _ = write!(name, "{byte:02x}");
        }
        self.root.join(name)
    }

    fn path_of(&self, file_id: &FileId, index: u64) -> PathBuf {
        self.dir_of(file_id).join(index.to_string())
    }
}

fn io_err(error: std::io::Error) -> StoreError {
    StoreError::Backend(error.to_string())
}

impl ChunkSource for FsBlobs {
    fn read_at(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(path).map_err(io_err)?;
        file.seek(SeekFrom::Start(offset)).map_err(io_err)?;
        let mut buffer = vec![0u8; len];
        let mut filled = 0;
        // `read` вправе вернуть меньше запрошенного и не в конце файла —
        // читаем, пока не наберём или пока файл не кончится. `read_exact`
        // здесь не годится: последний чанк короче остальных по построению.
        while filled < len {
            match file.read(&mut buffer[filled..]).map_err(io_err)? {
                0 => break,
                n => filled += n,
            }
        }
        buffer.truncate(filled);
        Ok(buffer)
    }

    fn chunk(&self, file_id: &FileId, index: u64) -> Result<Option<Vec<u8>>> {
        match std::fs::read(self.path_of(file_id, index)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_err(error)),
        }
    }
}

impl Blobs for FsBlobs {
    fn size_of(&self, path: &Path) -> Result<u64> {
        Ok(std::fs::metadata(path).map_err(io_err)?.len())
    }

    fn reader(&self) -> Box<dyn ChunkSource + Send + Sync> {
        // Клон — это клон пути, а не байтов: доступ к диску состояния
        // не имеет.
        Box::new(self.clone())
    }

    fn put_chunk(&mut self, file_id: &FileId, index: u64, sealed: &[u8]) -> Result<()> {
        let dir = self.dir_of(file_id);
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        // Без временного файла и переименования: оборванная запись даёт чанк,
        // который не пройдёт проверку тега, а отметка «принят» ставится
        // только после возврата отсюда — значит его просто попросят снова.
        std::fs::write(self.path_of(file_id, index), sealed).map_err(io_err)
    }

    fn remove(&mut self, file_id: &FileId) -> Result<()> {
        match std::fs::remove_dir_all(self.dir_of(file_id)) {
            Ok(()) => Ok(()),
            // Удалять нечего — не ошибка: передачу могли отменить до первого
            // принятого чанка.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_err(error)),
        }
    }

    fn remove_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        match std::fs::remove_file(self.path_of(file_id, index)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_err(error)),
        }
    }

    fn stored_files(&self) -> Result<Vec<FileId>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            // Каталога нет — значит не принято ни одного вложения. Это
            // пустой ответ, а не отказ: каталог заводится первой записью.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_err(error)),
        };

        let mut found = Vec::new();
        for entry in entries {
            let name = entry.map_err(io_err)?.file_name();
            // Чужое имя пропускается молча. Уборка не вправе трогать то, чего
            // не понимает: в этом каталоге может оказаться что угодно от
            // системы или от пользователя, и стирать это — не наше дело.
            let Some(name) = name.to_str() else { continue };
            let Some(file_id) = file_id_from_hex(name) else { continue };
            found.push(file_id);
        }
        found.sort_unstable();
        Ok(found)
    }

    fn stored_chunks(&self, file_id: &FileId) -> Result<Vec<(u64, u64)>> {
        let entries = match std::fs::read_dir(self.dir_of(file_id)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_err(error)),
        };

        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io_err)?;
            // Имя обязано совпасть с тем, что мы бы написали сами: разбор
            // «на глаз» принял бы и `+5`, и `007`, а удалять по такому имени
            // мы пошли бы в файл `5` и `7` — не в тот, что нашли.
            let name = entry.file_name();
            let Some(index) = name
                .to_str()
                .and_then(|n| n.parse::<u64>().ok().filter(|index| index.to_string() == n))
            else {
                continue;
            };
            let size = entry.metadata().map_err(io_err)?.len();
            found.push((index, size));
        }
        found.sort_unstable();
        Ok(found)
    }
}

/// Разбирает имя каталога обратно в идентификатор файла.
///
/// `None` — имя не наше: не тридцать два шестнадцатеричных знака.
fn file_id_from_hex(name: &str) -> Option<FileId> {
    // Проверка посимвольная, а не «разберётся ли»: `from_str_radix` принимает
    // ведущий плюс и заглавные буквы, то есть согласился бы на имя, которого
    // мы никогда не писали. Уборка стирает найденное — ошибиться тут значит
    // стереть чужое.
    if name.len() != 32 || !name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let bytes = name.as_bytes();
    let mut file_id = [0u8; 16];
    for (at, pair) in bytes.chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        file_id[at] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(file_id)
}

/// Байты в памяти — для симуляции и тестов (§16).
///
/// Умеет и то, чего у настоящего диска не спрашивают: [`MemoryBlobs::seed`]
/// кладёт «исходный файл» по пути, чтобы отправку можно было проверить,
/// не создавая ничего на диске.
#[derive(Debug, Default, Clone)]
pub struct MemoryBlobs {
    chunks: BTreeMap<(FileId, u64), Vec<u8>>,
    files: BTreeMap<PathBuf, Vec<u8>>,
}

impl MemoryBlobs {
    /// Пустое хранилище.
    #[must_use]
    pub fn new() -> MemoryBlobs {
        MemoryBlobs::default()
    }

    /// Кладёт «файл на диске» по пути — то, что отправитель будет читать.
    pub fn seed(&mut self, path: impl Into<PathBuf>, bytes: Vec<u8>) {
        self.files.insert(path.into(), bytes);
    }

    /// Убирает «файл с диска» — так проверяется исчезнувший исходник.
    pub fn forget(&mut self, path: impl AsRef<Path>) {
        self.files.remove(path.as_ref());
    }

    /// Содержимое собранного файла по пути.
    #[must_use]
    pub fn file(&self, path: impl AsRef<Path>) -> Option<&[u8]> {
        self.files.get(path.as_ref()).map(Vec::as_slice)
    }

    /// Сколько чанков лежит на всех файлах.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

impl ChunkSource for MemoryBlobs {
    fn read_at(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
        let bytes = self
            .files
            .get(path)
            .ok_or_else(|| StoreError::Backend(format!("нет файла {}", path.display())))?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(bytes.len());
        let end = start.saturating_add(len).min(bytes.len());
        Ok(bytes[start..end].to_vec())
    }

    fn chunk(&self, file_id: &FileId, index: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.chunks.get(&(*file_id, index)).cloned())
    }
}

impl Blobs for MemoryBlobs {
    fn size_of(&self, path: &Path) -> Result<u64> {
        self.files
            .get(path)
            .map(|bytes| bytes.len() as u64)
            .ok_or_else(|| StoreError::Backend(format!("нет файла {}", path.display())))
    }

    /// **Снимок, а не второй доступ.** У памяти байты и есть состояние,
    /// разделить его клонированием нельзя. Для тестов этого хватает, а там,
    /// где нужен именно общий доступ, берут `Arc<Mutex<MemoryBlobs>>` —
    /// у него `reader` честный.
    fn reader(&self) -> Box<dyn ChunkSource + Send + Sync> {
        Box::new(self.clone())
    }

    fn put_chunk(&mut self, file_id: &FileId, index: u64, sealed: &[u8]) -> Result<()> {
        self.chunks.insert((*file_id, index), sealed.to_vec());
        Ok(())
    }

    fn remove(&mut self, file_id: &FileId) -> Result<()> {
        self.chunks.retain(|(id, _), _| id != file_id);
        Ok(())
    }

    fn remove_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        self.chunks.remove(&(*file_id, index));
        Ok(())
    }

    fn stored_files(&self) -> Result<Vec<FileId>> {
        let mut found: Vec<FileId> = self.chunks.keys().map(|(id, _)| *id).collect();
        found.dedup();
        Ok(found)
    }

    fn stored_chunks(&self, file_id: &FileId) -> Result<Vec<(u64, u64)>> {
        Ok(self
            .chunks
            .range((*file_id, 0)..=(*file_id, u64::MAX))
            .map(|((_, index), bytes)| (*index, bytes.len() as u64))
            .collect())
    }
}

/// Разделяемая память — для тестов и симуляции (§16).
///
/// Ядро владеет своим хранилищем байтов целиком (`Box<dyn Blobs>`), и это
/// правильно: подглядывать в чужие чанки некому. Но тесту нужно и положить
/// исходный файл «на диск» отправителю, и заглянуть в принятое у получателя —
/// поэтому ссылка на одну и ту же память тоже умеет быть хранилищем.
///
/// Отравленный `Mutex` здесь трактуется как отказ хранилища: паниковать
/// второй раз следом за чужой паникой незачем.
impl ChunkSource for std::sync::Arc<std::sync::Mutex<MemoryBlobs>> {
    fn read_at(&self, path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
        locked(self)?.read_at(path, offset, len)
    }

    fn chunk(&self, file_id: &FileId, index: u64) -> Result<Option<Vec<u8>>> {
        locked(self)?.chunk(file_id, index)
    }
}

impl Blobs for std::sync::Arc<std::sync::Mutex<MemoryBlobs>> {
    fn size_of(&self, path: &Path) -> Result<u64> {
        locked(self)?.size_of(path)
    }

    fn reader(&self) -> Box<dyn ChunkSource + Send + Sync> {
        // Тот же самый набор байтов, а не снимок: ссылка на общую память.
        Box::new(std::sync::Arc::clone(self))
    }

    fn put_chunk(&mut self, file_id: &FileId, index: u64, sealed: &[u8]) -> Result<()> {
        locked(self)?.put_chunk(file_id, index, sealed)
    }

    fn remove(&mut self, file_id: &FileId) -> Result<()> {
        locked(self)?.remove(file_id)
    }

    fn remove_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        locked(self)?.remove_chunk(file_id, index)
    }

    fn stored_files(&self) -> Result<Vec<FileId>> {
        locked(self)?.stored_files()
    }

    fn stored_chunks(&self, file_id: &FileId) -> Result<Vec<(u64, u64)>> {
        locked(self)?.stored_chunks(file_id)
    }
}

fn locked(
    shared: &std::sync::Arc<std::sync::Mutex<MemoryBlobs>>,
) -> Result<std::sync::MutexGuard<'_, MemoryBlobs>> {
    shared.lock().map_err(|_| StoreError::Backend("хранилище байтов отравлено".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_round_trip(blobs: &mut dyn Blobs) {
        blobs.put_chunk(&[1u8; 16], 0, b"pervyj").unwrap();
        blobs.put_chunk(&[1u8; 16], 1, b"vtoroj").unwrap();
        assert_eq!(blobs.chunk(&[1u8; 16], 0).unwrap().as_deref(), Some(&b"pervyj"[..]));
        assert_eq!(blobs.chunk(&[1u8; 16], 5).unwrap(), None, "чанка нет — это не ошибка");

        blobs.remove(&[1u8; 16]).unwrap();
        assert_eq!(blobs.chunk(&[1u8; 16], 0).unwrap(), None);
        blobs.remove(&[1u8; 16]).unwrap();
    }

    /// Перечисление и поштучное удаление — то, на чём стоит уборка.
    ///
    /// Обе реализации обязаны отвечать одинаково: уборка сверяет диск
    /// с базой, и расхождение здесь означало бы, что симуляция (§16)
    /// проверяет не то, что делает продукт.
    fn check_listing(blobs: &mut dyn Blobs) {
        assert!(blobs.stored_files().unwrap().is_empty(), "пустое хранилище не выдумывает файлов");

        blobs.put_chunk(&[2u8; 16], 0, b"aaa").unwrap();
        blobs.put_chunk(&[2u8; 16], 7, b"bbbbb").unwrap();
        blobs.put_chunk(&[3u8; 16], 0, b"c").unwrap();

        assert_eq!(blobs.stored_files().unwrap(), vec![[2u8; 16], [3u8; 16]]);
        assert_eq!(blobs.stored_chunks(&[2u8; 16]).unwrap(), vec![(0, 3), (7, 5)]);
        assert!(
            blobs.stored_chunks(&[9u8; 16]).unwrap().is_empty(),
            "у неизвестного файла чанков нет — это не отказ"
        );

        blobs.remove_chunk(&[2u8; 16], 7).unwrap();
        assert_eq!(blobs.stored_chunks(&[2u8; 16]).unwrap(), vec![(0, 3)]);
        blobs.remove_chunk(&[2u8; 16], 7).unwrap();

        blobs.remove(&[2u8; 16]).unwrap();
        blobs.remove(&[3u8; 16]).unwrap();
    }

    #[test]
    fn memory_blobs_list_what_they_hold() {
        check_listing(&mut MemoryBlobs::new());
    }

    #[test]
    fn fs_blobs_list_what_they_hold() {
        let root = in_temp("listing");
        check_listing(&mut FsBlobs::new(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stranger_in_the_directory_is_left_alone() {
        // Уборка стирает то, что нашла, — значит перечисление обязано быть
        // разборчивым. Каталог рядом с базой может содержать что угодно
        // от системы; принять чужое имя за наше значит стереть чужое.
        let root = in_temp("strangers");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Thumbs.db")).unwrap();
        std::fs::create_dir_all(root.join("00112233445566778899AABBCCDDEEFF")).unwrap();
        std::fs::create_dir_all(root.join("00112233445566778899aabbccddee")).unwrap();

        let mut blobs = FsBlobs::new(&root);
        assert!(
            blobs.stored_files().unwrap().is_empty(),
            "имя не из тридцати двух строчных шестнадцатеричных знаков — не наше"
        );

        let mine = [0x0au8; 16];
        blobs.put_chunk(&mine, 0, b"moe").unwrap();
        assert_eq!(blobs.stored_files().unwrap(), vec![mine]);

        // Файл с именем, которое мы бы сами не написали, тоже не наш.
        std::fs::write(root.join("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a").join("007"), b"x").unwrap();
        assert_eq!(
            blobs.stored_chunks(&mine).unwrap(),
            vec![(0, 3)],
            "`007` — не номер чанка: удалять по нему пошли бы в файл `7`"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    fn in_temp(what: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ratatosk-blobs-{what}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn memory_blobs_round_trip() {
        check_round_trip(&mut MemoryBlobs::new());
    }

    #[test]
    fn fs_blobs_round_trip() {
        let root = in_temp("round-trip");
        check_round_trip(&mut FsBlobs::new(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reading_past_the_end_returns_what_is_there() {
        // Последний чанк короче остальных по построению, и читать его надо
        // так же, как любой другой: обе реализации обязаны отдать хвост,
        // а не отказать.
        let mut blobs = MemoryBlobs::new();
        blobs.seed("/tmp/a", b"rovno desyat".to_vec());
        assert_eq!(blobs.size_of(Path::new("/tmp/a")).unwrap(), 12);
        assert_eq!(blobs.read_at(Path::new("/tmp/a"), 6, 100).unwrap(), b"desyat");
        assert!(blobs.read_at(Path::new("/tmp/a"), 100, 10).unwrap().is_empty());
    }
}
