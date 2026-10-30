# AdGuard: маршруты из фактических DNS-ответов

Опциональный DNS-прокси пересылает запросы вашему AdGuard Home и обновляет
IPv4-маршруты по тому же ответу, который получает клиент. Опрос журнала,
учётная запись AdGuard и SSH не нужны. Настройки самого AdGuard не меняются.

```text
Обычно:  устройства → DNS MikroTik → DNS-прокси → AdGuard
                                    └─ IPv4 → BIRD → BGP → MikroTik
Авария:  устройства → DNS MikroTik ─────────────→ AdGuard
```

## Запуск

Требуется Linux-хост с Docker Compose v2. `BIRD_IP` должен принадлежать
этому хосту и отличаться от адреса AdGuard; порт 53 TCP/UDP на нём должен
быть свободен. В `.env` вместе с обычными настройками BGP задайте:

```dotenv
DNS_PROXY_ENABLED=1
COMPOSE_PROFILES=dns
ADGUARD_DNS=192.168.88.16
UPDATER_COMPOSE_SERVICES=bird admin dns-proxy
```

Прокси слушает `BIRD_IP:53`; проверка готовности доступна на
`http://BIRD_IP:8053/ready`. Разрешённый клиент по умолчанию — только `MT_IP`
и сам хост. Если LAN-адрес MikroTik отличается от BGP-адреса, задайте
`DNS_PROXY_ALLOWED_CLIENTS=192.168.88.1/32` с вашим адресом.

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `DNS_PROXY_BIND` | `BIRD_IP` | Конкретный локальный IPv4 для DNS и HTTP |
| `DNS_PROXY_ALLOWED_CLIENTS` | `MT_IP/32` | Разрешённые CIDR через запятую |
| `DNS_PROXY_PORT` | `53` | DNS TCP/UDP; для скрипта MikroTik оставьте 53 |
| `DNS_PROXY_HEALTH_PORT` | `8053` | HTTP-порт проверки |
| `ADGUARD_DNS_PORT` | `53` | Порт upstream AdGuard |
| `DNS_ROUTE_GRACE` | `30` | Дополнительное время хранения IP после TTL, секунд |
| `DNS_HEALTH_DOMAIN` | `example.org` | Домен проверки; AdGuard должен разрешать его |

```sh
docker compose up -d --build
docker compose logs -f dns-proxy
curl --fail http://YOUR_BIRD_IP:8053/ready
```

Первоначальная генерация создаёт `generated/dns-policy.json`. До успешной
генерации и запуска BIRD проверка возвращает 503. Если интеграция включена
на существующем snapshot, дождитесь фонового обновления и ответа 200.

## MikroTik: автоматическое переключение

Устройства используют LAN-адрес MikroTik как DNS. Его DNS-сервис должен
принимать запросы из LAN (`allow-remote-requests=yes` и ваши обычные правила
firewall). DHCP, firewall и AdGuard скрипт не меняет.

Сгенерируйте `.rsc` для **фактического адреса** хоста с прокси:

```sh
python3 scripts/mikrotik-dns-failover.py \
  --proxy YOUR_BIRD_IP --direct 192.168.88.16 \
  --output generated/mikrotik-dns-failover.rsc
```

Загрузите файл через Files. Перед импортом сохраните текущую конфигурацию
командой `/export file=before-bgp-dns`. Затем:

```routeros
/import file-name=mikrotik-dns-failover.rsc
```

Скрипт для RouterOS 7 сразу устанавливает прямой DNS `192.168.88.16` и
создаёт два script и два scheduler с именами `bgp-dns-*`. Каждые 5 секунд:

- 3 успешные проверки подряд → единственный upstream меняется на прокси;
- 2 неудачные подряд → единственный upstream меняется на AdGuard;
- после перезагрузки → прямой режим до успешных проверок;
- при переходе очищается DNS-кеш MikroTik; стабильное состояние не вызывает
  записи настроек и сообщений в лог.

`/ready` проверяет оба реальных DNS-входа (UDP и TCP), прохождение запроса
через AdGuard, применение конфигурации BIRD и, при
`HEALTHCHECK_REQUIRE_BGP=1`, состояние BGP Established. Проверка выполняется
через Scheduler с нужными правами; проверка прав не отключается.

Просмотр и ручное включение прямого режима:

```routeros
/ip dns print
/system scheduler print where name~"bgp-dns"
/log print where message~"BGP DNS"
/system scheduler disable [find where name="bgp-dns-watch"]
/system script run bgp-dns-direct
```

Для удаления сначала включите прямой режим командами выше, удалите два
scheduler и два script `bgp-dns-*`, установите `DNS_PROXY_ENABLED=0`, очистите
`COMPOSE_PROFILES`, верните `UPDATER_COMPOSE_SERVICES=bird admin` и выполните
`docker compose up -d --build --remove-orphans`. При необходимости верните
свои прежние настройки DNS из экспорта.

## Обработка маршрутов

- У прокси нет своего DNS-кеша. Кеширование остаётся у AdGuard, MikroTik
  и клиентов; записи и DNSSEC-данные upstream передаются клиенту.
- Маршруты добавляются для `include-domains.txt`, доменов из
  `domain-list-urls.txt` и их поддоменов. Остальные запросы пересылаются.
  CNAME-цепочки и IPv4-подсказки HTTPS/SVCB учитываются.
- `exclude-domains.txt` и его поддомены имеют приоритет: адрес из ответа
  исключается даже из более крупного префикса. Статические исключения также
  имеют приоритет над новыми включениями.
- Если клиенты получили IP1 и IP2, сохраняются оба до TTL каждого ответа
  плюс `DNS_ROUTE_GRACE`. Повторный ответ продлевает срок и не запускает
  скачивание списков. Неглобальные IPv4, включая `0.0.0.0` и частные адреса,
  не превращаются в маршруты.
- Новый адрес передаётся клиенту после принятия конфигурации BIRD. При
  ошибке восстанавливается предыдущий snapshot, запрос получает SERVFAIL.
  BGP передаёт обновление асинхронно: подтверждение BIRD само по себе
  не подтверждает установку маршрута на MikroTik.
- Проект объявляет IPv4. AAAA и остальные записи передаются, но
  IPv6-маршруты эта интеграция не создаёт.
- При прямом режиме DNS работает через AdGuard; наблюдение новых ответов
  возобновляется после возврата на прокси.

Активные правила: `generated/dns-policy.json`; TTL-записи:
`generated/dns-leases.json`; фактические маршруты: `routes.conf` и
`routes.last-good.conf`. Короткая файловая блокировка `dns-apply.lock`
автоматически снимается ОС при завершении процесса. Обычный `status.json`
описывает последнюю полную генерацию; его счётчик не включает последующие
изменения по DNS.

## Проверка после установки

1. Запросите включённый домен через MikroTik; проверьте полученный IP:
   `docker compose exec bird birdc show route for RECEIVED_IP`.
2. `docker compose stop dns-proxy`: после двух неудачных проверок DNS
   MikroTik должен стать `192.168.88.16`, резолвинг должен продолжаться.
3. `docker compose start dns-proxy`: после трёх успешных проверок DNS
   должен вернуться на прокси.

Разработчикам: `python3 -m pip install -r requirements.txt`, затем
`python3 -m unittest discover -s tests`. Linux Docker smoke test проверяет
UDP/TCP, маршруты настоящего BIRD, сохранение IP после полной генерации
и ошибки 503/SERVFAIL при остановленном BIRD. Импорт и переключение на
физическом MikroTik проверяются отдельно.

Справка: [Scheduler](https://help.mikrotik.com/docs/spaces/ROS/pages/40992881/Scheduler),
[Fetch](https://help.mikrotik.com/docs/spaces/ROS/pages/8978514/Fetch),
[DNS](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS).
