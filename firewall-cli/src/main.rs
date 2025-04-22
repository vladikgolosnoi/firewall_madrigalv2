mod config;
use config::Config;
use std::io::Write;

use dialoguer::{Input, Select};
use pnet::datalink;
use std::{
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

fn main() {
    let config = match Config::from_file("config.yml") {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Ошибка загрузки config.yml: {}", e);
            return;
        }
    };

    println!("Загруженный конфиг:\n{:#?}", config);

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = Arc::clone(&running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Ошибка установки обработчика Ctrl+C");
    }

    loop {
        running.store(true, Ordering::SeqCst);

        if !show_main_menu(&running, &config) {
            break;
        }
    }

    println!("Программа завершена.");
}

fn show_main_menu(running: &Arc<AtomicBool>, config: &Config) -> bool {
    clear_screen();
    println!("Выберите действие:");
    let items = vec![
        "1. Запустить файрволл",
        "2. Настроить config.yml",
        "3. Выбрать интерфейс",
        "4. Выход",
    ];

    let selection = Select::new().items(&items).default(0).interact();

    match selection {
        Ok(choice) => match choice {
            0 => run_firewall(running, config),
            1 => configure_file(),
            2 => choose_interface(),
            3 => return false,
            _ => {}
        },
        Err(e) => {
            if e.to_string().contains("interrupted") {
                println!("\nВвод прерван пользователем. Возврат в меню...");
            } else {
                println!("\nОшибка ввода: {e}");
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    true
}

fn run_firewall(running: &Arc<AtomicBool>, config: &Config) {
    println!("Запуск файрволла (нажмите Ctrl+C для возврата в меню)");

    let mut args = vec![];

    // Разрешённые HTTP-протоколы и порты
    for (proto, port) in &config.allowed {
        args.push(format!("--allow-{}={}", proto, port));
    }

    // Блокировки по протоколу
    if config.blocked.tcp == "*" {
        args.push("--block-tcp".to_string());
    }
    if config.blocked.udp == "*" {
        args.push("--block-udp".to_string());
    }

    let command = format!("firewall {}", args.join(" "));

    println!("\nВыполняется команда:");
    println!("sudo {}\n", command);

    let _ = Command::new("sudo")
        .args(command.split_whitespace())
        .status();

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    println!("\nФайрволл остановлен. Возврат в главное меню...");
}

fn clear_screen() {
    print!("{esc}c", esc = 27 as char);
    let _ = std::io::stdout().flush();
}

fn configure_file() {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());

    match Command::new(editor).arg("config.yml").status() {
        Ok(status) if status.success() => {}
        Ok(_) => println!("Редактор завершился с ошибкой."),
        Err(e) => println!("Ошибка запуска редактора: {e}"),
    }
}

fn choose_interface() {
    println!("Выберите интерфейс:");

    let interfaces: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.name != "lo")
        .collect();

    for (i, iface) in interfaces.iter().enumerate() {
        println!("{}. {}", i + 1, iface.name);
    }

    let iface_input: Result<String, _> = Input::new()
        .with_prompt("Введите номер или имя интерфейса")
        .interact_text();

    match iface_input {
        Ok(input) => {
            let selected_iface = if let Ok(index) = input.parse::<usize>() {
                interfaces.get(index - 1).map(|iface| iface.name.clone())
            } else {
                Some(input.clone())
            };

            match selected_iface {
                Some(name) => {
                    println!("Выбранный интерфейс: {}", name);
                    // Хочешь — можно сохранить его в config.yml позже
                }
                None => println!("Некорректный выбор интерфейса."),
            }
        }
        Err(e) => {
            if e.to_string().contains("interrupted") {
                println!("Ввод прерван пользователем (Ctrl+C).");
            } else {
                println!("Ошибка ввода: {e}");
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}
