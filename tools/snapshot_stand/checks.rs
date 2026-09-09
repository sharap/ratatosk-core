
fn told(onion: &str, ygg: Vec<u8>, peers: &[&str]) -> Client {
    Client {
        cache: Cache { chats: 3 },
        phone_onion: onion.to_owned(),
        phone_ygg: ygg,
        phone_ygg_peers: peers.iter().map(|p| (*p).to_owned()).collect(),
        addr_dirty: true,
    }
}

fn main() {
    let mut ok = 0;
    let mut bad = 0;
    let mut check = |что: &str, годно: bool| {
        if годно { ok += 1; } else { bad += 1; println!("ПРОВАЛ: {что}"); }
    };

    // 1. Круг: адрес и пиры переживают снимок.
    let mut writer = told("abc.onion", vec![7u8; 32], &["tls://a:1", "tcp://b:2"]);
    let sealed = writer.snapshot().expect("снимок");
    check("снимок снимает признак", !writer.addr_dirty);
    let mut cold = Client::default();
    cold.restore(&sealed).expect("подъём");
    check("onion вернулся", cold.phone_onion == "abc.onion");
    check("ключ меша вернулся", cold.phone_ygg == vec![7u8; 32]);
    check("пиры вернулись", cold.phone_ygg_peers.len() == 2);
    check("переписка вернулась", cold.cache.chats == 3);

    // 2. Снимок сборки постарше — без ключей адреса.
    let old = canonical::encode(&Cache { chats: 2 }.to_value()).expect("кодирование");
    let mut cold = Client { phone_ygg_peers: vec!["из-приглашения".into()], ..Client::default() };
    cold.restore(&old).expect("старый снимок обязан подниматься");
    check("старый снимок открылся", cold.cache.chats == 2);
    check("приглашение не затёрто", cold.phone_ygg_peers == vec!["из-приглашения".to_owned()]);

    // 3. Живой канал старше диска.
    let mut older = told("", Vec::new(), &["tls://прошлый:1"]);
    let stale = older.snapshot().expect("снимок");
    let mut live = told("abc.onion", vec![7u8; 32], &["tls://новый:1"]);
    live.restore(&stale).expect("подъём");
    check("объявленное не затёрто диском", live.phone_ygg_peers == vec!["tls://новый:1".to_owned()]);
    check("и ключ тоже", live.phone_ygg == vec![7u8; 32]);

    // 4. Пустой onion с диска — это «Tor был опущен», а не «оставь как было».
    let mut writer = told("", Vec::new(), &[]);
    let sealed = writer.snapshot().expect("снимок");
    let mut cold = Client { phone_onion: "из-приглашения.onion".into(), ..Client::default() };
    cold.restore(&sealed).expect("подъём");
    check("пустое с диска побеждает приглашение", cold.phone_onion.is_empty());

    // 5. Ключ не той длины с диска отвергается.
    for wrong in [31usize, 33] {
        let mut fields = match (Cache { chats: 1 }).to_value() {
            Value::Map(fields) => fields,
            _ => unreachable!(),
        };
        fields.push((Value::Integer(SNAP_KEY_YGG.into()), Value::Bytes(vec![1u8; wrong])));
        let bytes = canonical::encode(&Value::Map(fields)).expect("кодирование");
        let mut cold = Client::default();
        cold.restore(&bytes).expect("подъём");
        check("ключ не той длины отвергнут", cold.phone_ygg.is_empty());
    }

    // 6. Негодный пир выбрасывается поимённо, предел применяется на чтении.
    let mut fields = match (Cache { chats: 1 }).to_value() {
        Value::Map(fields) => fields,
        _ => unreachable!(),
    };
    let mut peers: Vec<Value> = vec![
        Value::Text("a".repeat(MAX_PEER_LEN + 1)),
        Value::Text(String::new()),
        Value::Integer(7.into()),
    ];
    peers.extend((0..MAX_YGG_PEERS + 5).map(|n| Value::Text(format!("tls://p{n}:1"))));
    fields.push((Value::Integer(SNAP_KEY_PEERS.into()), Value::Array(peers)));
    let bytes = canonical::encode(&Value::Map(fields)).expect("кодирование");
    let mut cold = Client::default();
    cold.restore(&bytes).expect("подъём");
    check("негодные выброшены, предел применён", cold.phone_ygg_peers.len() == MAX_YGG_PEERS);
    check("первым остался годный", cold.phone_ygg_peers[0] == "tls://p0:1");

    // 7. Ключи снимка не сталкиваются: кодек отвергает повторы.
    check("повторов ключей нет", writer.snapshot().is_ok());

    println!("прошло: {ok}, провалено: {bad}");
    std::process::exit(i32::from(bad != 0));
}
