<?php

// =====================
// 1. Проверка CSRF
// =====================
function checkForCsrfProtection($dir) {
    $csrfIssues = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir)) as $file) {
        if ($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
            $content = file_get_contents($file->getRealPath());
            if (preg_match('/\$_POST\s*\[.*\]/i', $content) && !preg_match('/csrf_token|check_csrf/i', $content)) {
                $csrfIssues[] = $file->getRealPath();
            }
        }
    }

    return $csrfIssues;
}

// =====================
// 2. Проверка проблем с сессиями
// =====================
function checkSessionSecurity($dir) {
    $sessionIssues = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir)) as $file) {
        if ($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
            $content = file_get_contents($file->getRealPath());
            if (preg_match('/session_start\s*\(\s*\)/i', $content)) {
                if (!preg_match('/session_regenerate_id\s*\(/i', $content)) {
                    $sessionIssues[] = [
                        'file' => $file->getRealPath(),
                        'issue' => 'Отсутствует вызов session_regenerate_id() для защиты от фиксации сессий.'
                    ];
                }
                if (!preg_match('/ini_set\s*\(\s*[\'\"]session\.cookie_secure[\'\"]\s*,\s*[\'\"]1[\'\"]\s*\)/i', $content)) {
                    $sessionIssues[] = [
                        'file' => $file->getRealPath(),
                        'issue' => 'Отсутствует настройка session.cookie_secure для защиты от передачи сессионных данных по незащищенному соединению.'
                    ];
                }
                if (!preg_match('/ini_set\s*\(\s*[\'\"]session\.cookie_httponly[\'\"]\s*,\s*[\'\"]1[\'\"]\s*\)/i', $content)) {
                    $sessionIssues[] = [
                        'file' => $file->getRealPath(),
                        'issue' => 'Отсутствует настройка session.cookie_httponly для защиты от XSS-атак.'
                    ];
                }
            }
        }
    }

    return $sessionIssues;
}

// =====================
// 3. Проверка авторизации
// =====================
function checkAuthorizationIssues($dir) {
    $authIssues = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir)) as $file) {
        if ($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
            $content = file_get_contents($file->getRealPath());
            if (preg_match('/\/\*.*NO_AUTH_REQUIRED.*\*\//', $content) || !preg_match('/if\s*\(!isset\(\$_SESSION\[[\"\']user[\"\']\]\)\)/i', $content)) {
                $authIssues[] = $file->getRealPath();
            }
        }
    }

    return $authIssues;
}

// =====================
// 4. Проверка утечек данных
// =====================
function checkForDataLeaks($dir) {
    $dataLeakPatterns = [
        '/error_log\s*\(/i' => 'Проблема: Логирование ошибок может содержать конфиденциальные данные.',
        '/define\s*\(\s*[\'\"](API_KEY|SECRET|PASSWORD)[\'\"]\s*,\s*[\'\"].*[\'\"]\s*\)/i' => 'Проблема: Жестко заданные конфиденциальные данные.',
        '/ini_set\s*\(\s*[\'\"]display_errors[\'\"]\s*,\s*[\'\"]1[\'\"]\s*\)/i' => 'Проблема: Включен вывод ошибок, который может раскрывать информацию о системе.'
    ];

    $dataLeakIssues = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir)) as $file) {
        if ($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
            $content = file_get_contents($file->getRealPath());
            foreach ($dataLeakPatterns as $pattern => $message) {
                if (preg_match($pattern, $content)) {
                    $dataLeakIssues[] = [
                        'file' => $file->getRealPath(),
                        'message' => $message
                    ];
                }
            }
        }
    }

    return $dataLeakIssues;
}

// =====================
// Генерация отчета
// =====================
function generateReport($issues, $filename = 'vulnerability_report.json') {
    $report = json_encode($issues, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    file_put_contents($filename, $report);
    echo "Отчет сохранен в: $filename" . PHP_EOL;
}

// =====================
// Автоисправление уязвимостей
// =====================
function autoFixVulnerabilities($dir) {
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir)) as $file) {
        if ($file->isFile() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
            $content = file_get_contents($file->getRealPath());
            // Пример исправления session.cookie_secure
            $content = preg_replace('/session_start\s*\(\s*\)/i', "ini_set('session.cookie_secure', '1');\nini_set('session.cookie_httponly', '1');\nsession_start();", $content);

            // Добавляем CSRF-проверку в обработчики POST
            if (preg_match('/\$_POST\s*\[.*\]/i', $content) && !preg_match('/csrf_token|check_csrf/i', $content)) {
                $content = preg_replace('/\$_POST\s*\[.*\]/i', "if (\$_POST['csrf_token'] !== \$_SESSION['csrf_token']) { die('CSRF Protection!'); }\n\$_POST", $content);
            }

            file_put_contents($file->getRealPath(), $content);
        }
    }
    echo "Базовые уязвимости исправлены." . PHP_EOL;
}

// =====================
// Основной запуск
// =====================
$dir = __DIR__;

echo "Запуск анализа..." . PHP_EOL;

// 1. Проверка CSRF
$csrfIssues = checkForCsrfProtection($dir);

// 2. Проверка сессий
$sessionIssues = checkSessionSecurity($dir);

// 3. Проверка авторизации
$authIssues = checkAuthorizationIssues($dir);

// 4. Проверка утечек данных
$dataLeakIssues = checkForDataLeaks($dir);

// Генерация отчета
$allIssues = [
    'csrf_issues' => $csrfIssues,
    'session_issues' => $sessionIssues,
    'authorization_issues' => $authIssues,
    'data_leak_issues' => $dataLeakIssues
];
generateReport($allIssues);

// Автоисправление (опционально)
// autoFixVulnerabilities($dir);

?>
