<?php
// Обработчик заявок: валидация, защита от спама, отправка в Telegram и на email.
// Настройки — в блоке CONFIG. Токены не храните в index.html.

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

/* ===== CONFIG ===== */
$CONFIG = [
    'email_to'      => '',                         // куда слать заявки ('' — отключить email; укажите ящик организации при публикации)
    'email_from'    => '',                         // адрес на домене сайта (важно для доставляемости)
    'tg_token'      => '',                         // токен бота от @BotFather ('' — отключить Telegram)
    'tg_chat_id'    => '',                         // ID чата/канала/пользователя (например, Telegram @andrey_club72)
    'site_host'     => 'svladimirko-arch.github.io',  // допустимый домен (проверка Origin). GitHub Pages PHP не исполняет — актуально при переносе на PHP-хостинг
    'min_fill_sec'  => 3,                          // быстрее — считаем ботом
    'max_per_hour'  => 5,                          // заявок с одного IP в час
];
/* ================== */

function out($ok, $msg = '', $code = 200) {
    http_response_code($code);
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(false, 'Method not allowed', 405);

// Проверка источника запроса
$origin = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
if ($origin !== '' && $CONFIG['site_host'] !== '' && stripos($origin, $CONFIG['site_host']) === false
    && stripos($origin, 'localhost') === false) {
    out(false, 'Forbidden', 403);
}

// Honeypot: поле скрыто от людей, боты его заполняют
if (!empty($_POST['website'])) out(true, 'ok'); // молча «успех», чтобы бот не подстраивался

// Слишком быстрая отправка
$ts = (int)($_POST['ts'] ?? 0);
if ($ts > 0 && (time() - intdiv($ts, 1000)) < $CONFIG['min_fill_sec']) out(true, 'ok');

// Ограничение частоты по IP (файловый счётчик)
$ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$dir  = sys_get_temp_dir() . '/lead_rl';
@mkdir($dir, 0700, true);
$file = $dir . '/' . md5($ip) . '.json';
$now  = time();
$hits = [];
if (is_file($file)) {
    $hits = json_decode((string)@file_get_contents($file), true) ?: [];
    $hits = array_values(array_filter($hits, fn($t) => $t > $now - 3600));
}
if (count($hits) >= $CONFIG['max_per_hour']) out(false, 'Слишком много заявок', 429);

// Очистка и валидация
function clean($s, $max) {
    $s = trim(strip_tags((string)$s));
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $s);
    return mb_substr($s, 0, $max);
}
$name    = clean($_POST['name'] ?? '', 60);
$phone   = clean($_POST['phone'] ?? '', 25);
$service = clean($_POST['service'] ?? '', 60);
$comment = clean($_POST['comment'] ?? '', 500);
$agree   = !empty($_POST['agree']);

$digits = preg_replace('/\D/', '', $phone);
if (mb_strlen($name) < 2)          out(false, 'Укажите имя', 422);
if (strlen($digits) !== 11 || $digits[0] !== '7') out(false, 'Неверный телефон', 422);
if (!$agree)                       out(false, 'Нужно согласие', 422);

// Антиспам по содержимому: ссылки в комментарии
if (preg_match('~https?://|www\.|\.(ru|com|net|org)/~i', $comment . ' ' . $name)) out(true, 'ok');

$text = "🛠 Новая заявка с сайта\n"
      . "Имя: $name\n"
      . "Телефон: +$digits\n"
      . "Услуга: $service\n"
      . ($comment !== '' ? "Комментарий: $comment\n" : '')
      . "Время: " . date('d.m.Y H:i') . "\n"
      . "IP: $ip";

$sent = false;

// Telegram
if ($CONFIG['tg_token'] !== '' && $CONFIG['tg_chat_id'] !== '') {
    $ch = curl_init('https://api.telegram.org/bot' . $CONFIG['tg_token'] . '/sendMessage');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => ['chat_id' => $CONFIG['tg_chat_id'], 'text' => $text],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
    ]);
    $res = curl_exec($ch);
    $j = json_decode((string)$res, true);
    if (!empty($j['ok'])) $sent = true;
    curl_close($ch);
}

// Email
if ($CONFIG['email_to'] !== '') {
    $subject = '=?UTF-8?B?' . base64_encode('Новая заявка: ' . $service) . '?=';
    $headers = "From: {$CONFIG['email_from']}\r\n"
             . "Content-Type: text/plain; charset=UTF-8\r\n";
    if (@mail($CONFIG['email_to'], $subject, $text, $headers)) $sent = true;
}

if (!$sent) {
    error_log('lead: delivery failed');
    out(false, 'Не удалось отправить', 500);
}

$hits[] = $now;
@file_put_contents($file, json_encode($hits), LOCK_EX);
out(true, 'ok');
