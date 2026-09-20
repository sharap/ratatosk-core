//! Уборка (§12): то, что растёт само и обязано убираться само.
//!
//! Спека говорит прямо: без уборки база перестанет открываться
//! на третий год. Ошибка такого рода проявляется не падением,
//! а медленной деградацией, и на стенде её не увидеть.

use super::*;

impl<S: Store> Engine<S> {
    /// Прибирается, если пора (§12).
    ///
    /// «Compaction обязателен с первого дня. Иначе клиент перестанет
    /// открываться на третий год» — и до этой функции он был написан целиком,
    /// но не запускался ни разу: [`Store::compact`] звали только тесты. Ошибка
    /// ровно того рода, о котором предупреждает спецификация: она проявляется
    /// не падением, а медленной деградацией, и на стенде её не увидеть.
    ///
    /// **По событию, а не по таймеру.** Телефон значительную часть времени
    /// спит (§13.1), и таймер там не гарантирует ничего; поэтому проверка
    /// делается после каждого шага ядра, а условие берётся из [`Schedule`]:
    /// накопилось довольно сообщений **или** прошло довольно времени.
    ///
    /// Возвращает число убранных строк — ноль означает и «было нечего»,
    /// и «ещё не пора».
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn compact_if_due(&mut self, now_ms: u64) -> Result<u64, EngineError> {
        let last = self
            .store
            .meta(ratatosk_store::META_LAST_COMPACTION)?
            .and_then(|raw| <[u8; 8]>::try_from(raw.as_slice()).ok())
            .map_or(0, u64::from_be_bytes);
        if !self.schedule.due(self.messages_since_compaction, last, now_ms) {
            return Ok(0);
        }

        // Отметка ставится **до** работы, а не после. Уборка, падающая
        // на какой-то одной задаче, иначе повторялась бы на каждом шаге
        // ядра — то есть отказ хранилища превращался бы в бесконечный цикл
        // отказов. Пропустить один круг дешевле.
        self.store.put_meta(ratatosk_store::META_LAST_COMPACTION, &now_ms.to_be_bytes())?;
        self.messages_since_compaction = 0;

        let mut removed = 0;
        for task in Task::ALL {
            // Отказ одной задачи не отменяет остальные: они независимы,
            // и не убрать всё — лучше, чем не убрать ничего.
            match self.store.compact(task, now_ms) {
                Ok(rows) => removed += rows,
                Err(error) => tracing::warn!(?task, ?error, "задача уборки не выполнена"),
            }
        }
        // Свёртка состава живёт **здесь, а не в хранилище**: знак выбирает
        // протокол, а свёрнутый состав считает `Group`. Таблица про то
        // и другое не знает ничего, и задачей хранилища это было бы
        // только по названию.
        removed += self.fold_old_membership(now_ms);
        Ok(removed)
    }

    /// Стирает с диска вложения, которых нет в базе (§12).
    ///
    /// Байты вложений живут не в базе, а рядом с ней ([`ratatosk_store::Blobs`]),
    /// и это правильно: двухгигабайтный BLOB в SQLite — переписанная страница
    /// на каждый чанк и WAL размером с файл. Но у раздельного хранения есть
    /// своя цена, и вот она: база и диск способны разойтись, а база о том,
    /// что осталось на диске, не знает ничего.
    ///
    /// Расходятся они двумя путями, и оба настоящие. Удаление контакта вместе
    /// с историей сносит сообщения, каскад внешних ключей уносит записи
    /// о файлах — а каталоги с чанками остаются лежать; переписка на гигабайт
    /// исчезала из базы, не освободив ни байта. И удаление сообщения намеренно
    /// проглатывает отказы удаления байтов: незавершённое удаление сообщения
    /// хуже, чем оставшийся на диске мусор, — но мусор остаётся.
    ///
    /// Поэтому сверка отдельной операцией, а не частью удаления: она чинит
    /// и то, что утекло вчера на устройстве, где эта функция ещё не работала.
    /// Направление у неё одно — **с диска убирается лишнее**, на диск ничего
    /// не добавляется. Запись в базе без байтов на диске мусором не является:
    /// это незаконченный приём, и продолжится он ровно с той дырки, которой
    /// не хватает (§10.2).
    ///
    /// Стирается два вида лишнего: целые каталоги вложений, о которых в базе
    /// нет ни строчки, и отдельные чанки, не отмеченные принятыми, — след
    /// процесса, убитого системой между записью байтов и отметкой о них
    /// (порядок этих двух шагов сознательный, см. [`ratatosk_store::Blobs`]).
    /// Такой чанк не читается никогда: его перепросят и перезапишут.
    ///
    /// Дорогая: обходит каталог целиком. Звать по кнопке «освободить место»
    /// или в редкой фоновой уборке, но не по событию.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или диска. Убранное до отказа остаётся убранным:
    /// уборка не транзакция, и делать её транзакцией незачем — повторный
    /// запуск просто доделает остальное.
    pub fn sweep_orphan_files(&mut self) -> Result<Swept, EngineError> {
        self.sweep_abandoned_uploads(0)
    }

    /// Вывозит переписку в зашифрованный архив (§12).
    ///
    /// **Единственный путь переноса истории на другое устройство в v1** —
    /// так это названо в §12, и других не появится: ни синхронизации,
    /// ни облака в v1 нет. Без архива переписка человека живёт ровно
    /// столько, сколько его телефон.
    ///
    /// В архив кладётся снимок базы (печатает хранилище, ключ за его
    /// пределы не выходит) и **все куски вложений как есть**: они уже
    /// запечатаны своим ключом (§10.1), а ключ файла лежит в базе.
    ///
    /// Ключ архива возвращается строкой для показа человеку. Показать его
    /// обязательно и обязательно **сразу**: второй раз этот же архив
    /// не спросишь, а без ключа он не открывается нигде.
    ///
    /// Дорогая: переписывает базу и все вложения. Звать по кнопке,
    /// а не по расписанию.
    ///
    /// # Errors
    ///
    /// Отказ хранилища, диска или уже существующий файл по этому пути:
    /// перезаписать чужой архив молча нельзя — под ним может лежать
    /// единственная копия чьей-то переписки.
    pub fn export_history(
        &mut self,
        destination: &Path,
        scope: ExportScope,
        phrase: Option<&str>,
    ) -> Result<Exported, EngineError> {
        use ratatosk_store::archive::{ArchiveSink, ArchiveWriter, EntryKind, Header, KeyWrap};

        // Ключ спрашивается **первым**: у хранилища в памяти его нет, и
        // узнать об этом лучше до того, как на диске появится пустой файл.
        let key = self.store.export_key()?;

        if destination.exists() {
            return Err(EngineError::Store(ratatosk_store::StoreError::Backend(
                "файл по этому пути уже есть — под ним может лежать чужой архив".into(),
            )));
        }
        let file = std::fs::File::create(destination)
            .map_err(|e| ratatosk_store::StoreError::Backend(format!("архив не создать: {e}")))?;
        // Идентификатор архива — из того же источника случайности, что и
        // идентификаторы сообщений: шестнадцать байт, и повторяться им
        // нельзя (см. `archive::db_chunk_aad`).
        let archive_id = self.entropy.msg_id();
        let header = Header { archive_id, scope };
        let mut writer = ArchiveWriter::start(std::io::BufWriter::new(file), header)
            .map_err(|e| ratatosk_store::StoreError::Backend(format!("архив не начат: {e}")))?;

        // **Завёрнутый ключ — первой записью**, до всего остального: куски
        // базы им открываются, а читает архив тот, кто идёт по нему потоком.
        //
        // Кладётся, только если человек назвал фразу. Без неё архив
        // открывается сырым ключом — так делались все архивы до появления
        // фразы, и так же делаются те, что уезжают в автоматический бэкап,
        // где придумывать фразу некому.
        if let Some(phrase) = phrase {
            if phrase.trim().is_empty() {
                return Err(EngineError::Store(ratatosk_store::StoreError::Backend(
                    "пустая фраза не защищает ничего — либо фраза, либо ключ".into(),
                )));
            }
            let mut salt = [0u8; ratatosk_store::archive::WRAP_SALT_LEN];
            self.entropy.fill(&mut salt);
            let params = ratatosk_crypto::storage_key::KdfParams::default();
            let from_phrase = ratatosk_crypto::storage_key::derive_from_pin(phrase, &salt, params)?;
            let sealed = ratatosk_crypto::storage_key::seal_field(
                &from_phrase,
                &ratatosk_store::archive::wrapped_key_aad(&archive_id),
                &key[..],
            )?;
            let wrap = KeyWrap {
                salt,
                memory_kib: params.memory_kib,
                iterations: params.iterations,
                parallelism: params.parallelism,
                sealed,
            };
            writer.put(EntryKind::WrappedKey, &[0u8; 16], 0, &wrap.to_bytes()).map_err(|e| {
                ratatosk_store::StoreError::Backend(format!("ключ не записался: {e}"))
            })?;
        }

        self.store.export_into(scope, &mut writer)?;

        // Вложения — после базы и **все**, включая те, что ещё едут:
        // приём продолжится на новом устройстве с той же дырки (§10.2),
        // а выброшенный на полпути кусок пришлось бы качать заново.
        //
        // Область решает, едут ли они вообще. Без вложений архив легче
        // на порядок и уезжает почтой — но записи о них в базе остаются,
        // и ввоз обязан прочесть область (`ExportScope`), а не догадываться
        // по тому, что вложений не встретилось.
        let mut files = 0u64;
        if scope.carries_attachments() {
            for file_id in self.blobs.stored_files()? {
                for (index, _) in self.blobs.stored_chunks(&file_id)? {
                    let Some(bytes) = self.blobs.chunk(&file_id, index)? else { continue };
                    writer.put(EntryKind::Attachment, &file_id, index, &bytes).map_err(|e| {
                        ratatosk_store::StoreError::Backend(format!("вложение не записалось: {e}"))
                    })?;
                }
                files += 1;
            }
        }

        let (_, bytes) = writer
            .finish()
            .map_err(|e| ratatosk_store::StoreError::Backend(format!("архив не закрыт: {e}")))?;

        Ok(Exported {
            path: destination.to_path_buf(),
            scope,
            // Ключ отдаётся **всегда**, даже когда архив заперт фразой:
            // это второй вход, и место ему — в менеджере паролей. Человек,
            // забывший фразу через пять лет, иначе остался бы ни с чем.
            key_text: ratatosk_crypto::storage_key::key_text(&key),
            locked_by_phrase: phrase.is_some(),
            files,
            bytes,
        })
    }

    /// То же, но сперва выбрасывает выгрузки, брошенные раньше срока.
    ///
    /// `now_ms` = 0 означает «срок не считать»: у сверки, вызванной вручную,
    /// часов нет, а выбрасывать чужие байты по неизвестному времени нельзя.
    ///
    /// **Срок нужен, потому что брошенную выгрузку никто не закрывает.**
    /// Десктоп, у которого сдох процесс посреди третьего файла, не пришлёт
    /// ни `FileSend`, ни `FileAbort`; его куски будут лежать в хранилище
    /// телефона до конца времён, а сверка сирот их не тронет — она их
    /// нарочно пропускает.
    pub fn sweep_abandoned_uploads(&mut self, now_ms: u64) -> Result<Swept, EngineError> {
        let mut swept = Swept::default();
        if now_ms > companion::STAGED_TTL_MS {
            for file_id in self.store.staged_older_than(now_ms - companion::STAGED_TTL_MS)? {
                swept.bytes +=
                    self.blobs.stored_chunks(&file_id)?.iter().map(|(_, size)| *size).sum::<u64>();
                swept.files += 1;
                self.uploads.retain(|upload| upload.file_id != file_id);
                self.store.delete_staged(&file_id)?;
                self.blobs.remove(&file_id)?;
            }
        }

        // **Файл без единой ссылки — тоже мусор.** Связку уносит каскадом
        // всякое удаление сообщения, в том числе уборка §12, которую ядро
        // не звало. Сверка каталога такой файл не ловит: для неё он
        // известен, строка-то есть, — и байты лежали бы до конца времён.
        for file_id in self.store.orphan_file_ids()? {
            swept.bytes +=
                self.blobs.stored_chunks(&file_id)?.iter().map(|(_, size)| *size).sum::<u64>();
            swept.files += 1;
            self.forget_file(&file_id);
        }

        let mut known: BTreeSet<FileId> = self.store.all_file_ids()?.into_iter().collect();
        // **Идущая выгрузка с десктопа — не сирота, хотя выглядит ею.** Её
        // куски уже лежат в хранилище, а строки в базе ещё нет и не должно
        // быть: сообщение заводится в конце (см. `Engine::uploads`). Сверка,
        // случившаяся посреди выгрузки, стёрла бы их молча — и отправка
        // упала бы на «кусок пропал» через минуту после уборки, никак с ней
        // не связанная на вид.
        known.extend(self.uploads.iter().map(|upload| upload.file_id));

        for file_id in self.blobs.stored_files()? {
            let chunks = self.blobs.stored_chunks(&file_id)?;
            if !known.contains(&file_id) {
                swept.bytes += chunks.iter().map(|(_, size)| *size).sum::<u64>();
                swept.files += 1;
                self.blobs.remove(&file_id)?;
                continue;
            }
            // Идущую передачу это не трогает: чанк отмечается в базе в том же
            // шаге, в котором ложится на диск, а уборка идёт между шагами.
            // Неотмеченный чанк здесь — всегда след прошлой жизни процесса.
            //
            // Кроме выгрузки с десктопа: там отметок в базе нет вовсе, потому
            // что нет и строки файла. Её куски пропускаются целиком.
            if self.uploads.iter().any(|upload| upload.file_id == file_id) {
                continue;
            }
            for (index, size) in chunks {
                if !self.store.has_chunk(&file_id, index)? {
                    self.blobs.remove_chunk(&file_id, index)?;
                    swept.chunks += 1;
                    swept.bytes += size;
                }
            }
        }
        Ok(swept)
    }
}
