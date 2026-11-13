# Sysmon

Лёгкий терминальный монитор систем Unix/Linux. Сохраняет исходный интерфейс на `curses` и использует `psutil` для системных показателей.

## Возможности

- **System** — uptime.
- **CPU** — текущая загрузка процессора.
- **Memory** — использование RAM и Swap.
- **Disk** — занятое место и скорость Disk I/O.
- **Network** — накопительный исходящий трафик (TX) за выбранный период и, при настройке, расход относительно лимита провайдера.

Статистика трафика собирается независимо от открытого интерфейса Sysmon. Сборщик запускается раз в минуту планировщиком ОС и завершает работу после одного измерения.

## Установка одной командой

Предварительное условие — установленный `git`, поскольку он нужен для клонирования репозитория:

```sh
git clone --branch development --single-branch https://github.com/Detsle/sysmon.git && cd sysmon && sh install.sh
```

Установщик:

1. Определяет ОС и доступный пакетный менеджер.
2. При необходимости устанавливает Python 3.8+ и компоненты для виртуального окружения.
3. Создаёт изолированное окружение `/opt/sysmon/venv`.
4. Устанавливает `psutil` (если для платформы требуется сборка из исходников, установщик дополнительно запросит системный компилятор и заголовки).
5. Устанавливает Sysmon в `/opt/sysmon` и создаёт команду `/usr/local/bin/sysmon`.
6. Сразу при установке создаёт базовый снимок исходящего счётчика — с этого момента начинается учёт.
7. Настраивает фоновый сбор: systemd timer на Linux с systemd; cron на Linux без systemd и BSD.
8. При первом запуске Sysmon запрашивает дату начала расчёта квоты и лимит трафика. Значения по умолчанию — текущая дата и Unlimited.

Установщик сам запросит повышение привилегий через `sudo` или `doas`, если он запущен обычным пользователем. Без них его нужно запускать от root.

## Запуск

```sh
sysmon
```

В блоке **Network** одной строкой отображаются период, исходящий трафик и квота. Клавиши:

- `P` — переключить период (Today / 7 days / 30 days / All time).
- `D` — изменить дату начала отображения трафика и расчёта квоты.
- `L` — изменить квоту в Gb или выбрать `Unlimited`.
- `Q` — выйти.

Блок **Hotkeys** постоянно показывает эти сочетания клавиш.

Для произвольного календарного диапазона:

```sh
sysmon --from-date 2026-11-01 --to-date 2026-11-13
```

Даты включаются в расчёт целиком.

## Traffic start date and quota

On the first launch, Sysmon asks for:

- Traffic start date in `DD.MM.YYYY` format (day/month/year); default: the current date. Blank or invalid input uses today's date.
- Traffic quota in decimal Gb; default: `Unlimited`. Blank or invalid input sets `Unlimited`.

The start date cannot be earlier than the installation date. A future start date is allowed: Traffic and a configured Quota usage display `-` until that date. The same start date is used to filter both the selected Traffic period and accumulated Quota usage. Invalid-input messages remain visible for five seconds.

Hotkeys:

- `D` — change the shared Traffic/Quota start date.
- `L` — change the quota in Gb or set it to `Unlimited`.

The start date applies to both Traffic and Quota; they cannot be configured independently. Blank date input sets today's date. Blank quota input sets `Unlimited`. Invalid date input falls back to today's date, and invalid quota input falls back to `Unlimited`. Error messages remain visible for five seconds.

Traffic, Memory, Disk, and Quota values use the requested `Gb`, `Mb`, and `Tb` labels, with a space before each unit. These labels are visual abbreviations only: Sysmon continues to count bytes, not bits. Values below 1,024 Gb are shown with one decimal place; at 1,024 Gb and above they are converted to Tb using 1,024 as the display divisor and shown with two decimal places. Memory and Disk retain binary byte conversion; Traffic and Quota retain decimal byte conversion. Used/total pairs display one shared unit at the end and use `|` as the separator. Disk I/O retains `Mb/s`, while the read/write separator is `|`. When the quota is `Unlimited`, the Quota field is hidden entirely while traffic collection continues. A 100,000 Gb preview is shown as 97.66 Tb and fits both Today and 30 days in the existing Network row.

Optional administrative commands:

```sh
sysmon --set-limit 2000Gb
sysmon --quota-start-date 13.11.2026
sysmon --clear-limit
```

Settings are stored in `traffic.json`. Run configuration commands as `root` or through `sudo`/`doas`; regular users only need read access to the statistics.

## Network layout preview

To inspect how large Traffic and Quota values fit into the existing Network panel, run:

```sh
sysmon --preview-network 100000Gb
```

This opens the normal curses interface with synthetic Network values. The supplied size is shown as Traffic and as both used/limit Quota values. Press `P` to cycle through periods and `Q` to exit. Preview mode skips first-run setup and disables date/quota editing. It does not read or modify the saved traffic history, quota settings, or collector baseline. Any supported size can be supplied, for example `500Gb`, `2Tb`, or `100000Gb`.

## Reset first-run setup

For testing the first-run prompts, reset only the date/quota setup:

```sh
sudo sysmon --reset-setup
sudo sysmon
```

The next launch asks for the Traffic start date and quota again. The reset restores the start-date default to the current date and the quota to `Unlimited`. It preserves the collected daily traffic, installation timestamp, selected network interface, and collector baseline. It does not restart or reset background traffic collection.

## Сетевой интерфейс

По умолчанию Sysmon определяет интерфейс основного маршрута по умолчанию и учитывает его `bytes_sent`. Известные loopback-, tunnel-, bridge- и container-интерфейсы не выбираются автоматически: если маршрут по умолчанию направлен через VPN-туннель, Sysmon пытается найти единственный активный физический интерфейс. Это помогает не учитывать один пакет дважды. При нескольких возможных физических интерфейсах автоматический выбор прекращается — нужно указать нужный интерфейс вручную.

Если автоматическое определение не соответствует сетевой конфигурации VPS, интерфейс можно указать вручную:

```sh
sysmon --interface eth0
```

Вернуть автоматическое определение:

```sh
sysmon --interface auto
```

## Фоновый сбор и данные

- Интервал сбора: 60 секунд.
- Данные: `/var/lib/sysmon/traffic.json`.
- Блокировка параллельного запуска: `/var/lib/sysmon/traffic.lock`.
- История хранится по календарным дням и не ограничена по сроку.
- JSON обновляется атомарной заменой файла.
- Счётчик сверяется с предыдущим значением; после перезагрузки учитываются байты, уже отправленные с момента загрузки ОС. При сбросе счётчика создаётся новая базовая точка, отрицательная разница не учитывается.

Учёт начинается с первого снимка счётчика при установке. Трафик, использованный до установки Sysmon, восстановить нельзя. При перезагрузке ОС интервал между последним измерением перед выключением и первым измерением после загрузки нельзя точно восстановить по системному счётчику. Также показания TX являются оценкой расхода по сетевому интерфейсу: методика округления и состав тарифицируемых данных конкретного VPS-провайдера могут отличаться.

## Поддерживаемые платформы

Целевые платформы первой версии (с учётом актуальной матрицы поддержки `psutil`):

- Linux: Debian/Ubuntu, RHEL-подобные, Fedora, Alpine, Arch, openSUSE и Gentoo — при наличии соответствующего пакетного менеджера и планировщика.
- FreeBSD.
- OpenBSD.
- NetBSD.

На Linux с systemd используется systemd timer. На остальных целевых платформах используется cron. Установка и автоматическое определение интерфейса вне этой матрицы пока не гарантируются. Для систем без стандартного пакетного менеджера или без доступного Python/сборочных компонентов установщик выдаст конкретную ошибку вместо частичной установки.

macOS не входит в целевую матрицу проекта.

## Разработка и тесты

```sh
python3 -m unittest discover -s tests -v
```

Sysmon намеренно не использует веб-интерфейс, базу данных-сервер, графики или постоянно работающий демон.