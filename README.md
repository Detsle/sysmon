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
8. При первом запуске Sysmon запрашивает только месячный лимит трафика. Пустое поле или некорректное значение означает Unlimited.

Установщик сам запросит повышение привилегий через `sudo` или `doas`, если он запущен обычным пользователем. Без них его нужно запускать от root.

## Запуск

```sh
sysmon
```

В блоке **Network** одной строкой отображаются период, исходящий трафик и квота. Клавиши:

- `P` — переключать Today / 7 days / 1 month / All time. `1 month` — текущий календарный месяц; клавиша работает вне истории.
- `M` — открыть историю по календарным месяцам; внутри истории повторное нажатие возвращает к текущему месяцу.
- `[` / `]` — перейти на предыдущий / следующий месяц. Клавиши работают только в режиме истории.
- `Esc` — внутри истории вернуться на предыдущий экран и восстановить открытый до неё период; в обычном режиме выйти из Sysmon.
- `L` — изменить месячный лимит в Tb или выбрать `Unlimited`; работает вне истории.
- `Q` — выйти из Sysmon; внутри истории эта клавиша не активна.

Если сбор трафика начинается не с первого числа месяца, этот первый месяц помечается `*` в поле `Period`; значение звёздочки объясняется при первом запуске. Выбранный стандартный период и месяц истории сохраняются в настройках. Если предыдущий сеанс завершился в истории, после нового запуска Sysmon откроется в `Today`; нажатие `M` вернёт к сохранённому месяцу. Внутри истории повторное нажатие `M` возвращает к текущему месяцу.

Блок **Hotkeys** показывает `M: months` в обычном режиме. После открытия истории через `M` остаются только `M: current`, `[ ]: browse` и `Esc: back`; возврат восстанавливает предыдущий экран и период. В обоих календарных месячных режимах — `1 month` и история через `M` — отображаются только период и расход трафика; поле `Quota` скрыто. При вводе квоты допустимы целые и десятичные значения с точкой, например `1` и `1.1`.

Для произвольного календарного диапазона:

```sh
sysmon --from-date 01-11-26 --to-date 13-11-26
```

Даты включаются в расчёт целиком. Формат ввода и отображения дат — `DD-MM-YY`; двузначный год трактуется как 2000–2099.

## Calendar-month Traffic and Quota

On the first launch, Sysmon asks only for the monthly Traffic quota in decimal Tb. Enter a whole number or a decimal number using a dot, for example `1` or `1.1`, without a unit suffix. Leaving the field blank applies `Unlimited`. Invalid input also falls back to `Unlimited`.
- Custom date ranges use `DD-MM-YY`; displayed custom dates use the same format.

Traffic is grouped by calendar months from the start of reliable collection. The first accounting month is partial when collection starts after the first day of that month; it is marked with `*` in the `Period` value. The first-run setup explains this marker. `P` cycles only `Today`, `7 days`, `1 month` (the current calendar month), and `All time` outside monthly history. The `M` key opens calendar-month history; only in that mode are `[` and `]` available for previous/next month navigation. Pressing `Esc` returns to the screen and standard period that were active before opening history. While history is open, its only active controls are `M` (current month), `[` / `]` (browse), and `Esc` (back); period switching, quota editing, and quitting are disabled. Both calendar-month views (`1 month` and history opened with `M`) show only the period and Traffic total; the `Quota` field is hidden. Month labels use the compact format `Jan ’26`. February contains 28 or 29 days depending on the year, while other months use their actual 30- or 31-day length.

The monthly Quota uses the same calendar boundaries and resets automatically on the first day of each month. The configured limit remains the same each month. The standard selected period and historical month are stored in `traffic.json`; legacy period values that are no longer available through `P` are reset to `Today`. If the previous session ended in monthly history, the next launch starts in `Today`; pressing `M` reopens the saved historical month. While history is open, pressing `M` returns to the current month, and `Esc` returns to the standard period that was active before entering history. When migrating a state file from a build that predates the outbound collector, Sysmon excludes daily records before 13 Nov 2026, the date the collector was introduced. Those older JSON entries are retained but are not included in traffic or quota totals, and month navigation starts at the first reliable collection month.

Hotkeys:

- `M` — open monthly history; while history is open, return to the current month.
- `[` / `]` — browse previous / next months inside history.
- `Esc` — return from history to the previous screen; exits Sysmon in the standard view.
- `L` — change the monthly quota or set it to `Unlimited` in the standard view.

Quota input accepts whole or decimal numbers using a dot (for example, `1` or `1.1`), without `Tb` or other suffixes. Leave the field empty to apply `Unlimited`. Invalid quota input falls back to `Unlimited`. Error messages remain visible for five seconds.

Traffic, Memory, Disk, and Quota values use the requested `Gb`, `Mb`, and `Tb` labels, with a space before each unit. These labels are visual abbreviations only: Sysmon continues to count bytes, not bits. Traffic uses decimal conversion: 1,000 Gb = 1 Tb. Traffic values below 1,000 Gb are shown in Gb; at 1,000 Gb and above they are converted to Tb and shown with two decimal places. Quota input is always in decimal Tb and accepts whole numbers or decimal numbers using a dot: enter `1` or `1.1`, without a unit suffix. Leave the interactive quota field blank to apply `Unlimited`. In views where Quota is displayed, the configured limit uses Tb and removes unnecessary trailing zeros (for example, `8 Tb`, `4.5 Tb`, or `0.5 Tb`); quota usage uses the same adaptive units as Traffic: Gb below 1 Tb and Tb with two decimal places from 1 Tb upward. Calendar-month views intentionally omit Quota. RAM and Disk totals use binary GiB-style units and retain one decimal place. Used values are rounded to one decimal place; total capacities are truncated to one decimal place so the display does not overstate the measured capacity. For example, 15.3 GiB of RAM is shown as `15.3 Gb`, and a 431.49 GiB filesystem is shown as `431.4 Gb`. Used/total pairs display one shared unit at the end and use `|` as the separator. Disk I/O retains `Mb/s`, while the read/write separator is `|`. When the quota is `Unlimited`, the Quota field is hidden entirely while traffic collection continues. A 100,000 Gb preview is shown as 100.00 Tb and fits the Today and 1 month Network rows.

Optional administrative commands:

```sh
sysmon --set-limit 8
sysmon --clear-limit
```

Settings are stored in `traffic.json`. Run configuration commands as `root` or through `sudo`/`doas`; regular users only need read access to the statistics.

## Network layout preview

To inspect how large Traffic and Quota values fit into the existing Network panel, run:

```sh
sysmon --preview-network 100000Gb
```

This opens the normal curses interface with synthetic Network values. The supplied size is shown as Traffic and as both used/limit Quota values. Press `P` to cycle through periods and `Q` to exit. Preview mode skips first-run setup and disables quota editing. It does not read or modify the saved traffic history, quota settings, or collector baseline. Any supported size can be supplied, for example `500Gb`, `2Tb`, or `100000Gb`.

## Reset first-run setup

For testing the first-run quota prompt, reset the quota setup:

```sh
sudo sysmon --reset-setup
sudo sysmon
```

The next launch asks for the monthly quota again. The reset restores the quota to `Unlimited` but preserves the selected period and historical month, as well as the collected daily traffic, installation timestamp, selected network interface, and collector baseline. It does not restart or reset background traffic collection.

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
- История хранится по календарным дням без автоматического удаления старых месяцев.
- История доступна с момента установки Sysmon; месяц установки может быть неполным.
- Размер истории обычно увеличивается лишь на десятки килобайт в год, в зависимости от числа записей и объёма чисел.
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