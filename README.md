# Portal samorządu uczniowskiego — 1.0

Gotowa aplikacja Python/Flask do własnego repozytorium GitHub i wdrożenia na Renderze. Jest to nowa aplikacja, a nie modyfikacja pliku Super dziennika.

## Funkcje

- Pulpit z informacjami o koncie i najbliższymi wydarzeniami.
- Kalendarz: opiekun i administrator dodają i usuwają wydarzenia; uczestnicy je przeglądają. Daty w polskiej strefie czasowej. Widok chronologicznej listy wydarzeń.
- Pomysły: uczeń widzi własne zgłoszenia; opiekun i administrator widzą wszystkie.
- Poczta: wiadomości do pojedynczego odbiorcy, foldery odebrane/wysłane, wiele załączników (zdjęcia, PDF i inne pliki), pobieranie tylko przez nadawcę lub odbiorcę. Limit 10 plików i 25 MB całego żądania. Pliki są pobierane, bez podglądu w przeglądarce.
- Skład trójki: opiekun tworzy konta uczniów i nadaje funkcję, zawiesza oraz odwiesza. Cztery funkcje: Przewodniczący, V-ce przewodniczący, Skarbnik, Sekretarz.
- Użytkownicy: administrator dodaje uczniów, opiekunów i kolejnych administratorów, usuwa konta, resetuje hasła, zawiesza i odwiesza. Nie może usunąć ani zawiesić siebie ani ostatniego aktywnego administratora.
- Profil: zmiana własnego hasła z weryfikacją obecnego oraz wybór jednego z pięciu kolorów.
- Zawieszone konto po zalogowaniu widzi tylko czerwony prostokąt: „zostałeś zawieszony skontaktuj się z opiekunem trójki”. Blokada obowiązuje także dla wcześniej otwartej sesji i pobierania plików. Odwieszenie przywraca dostęp.

## Wdrożenie na Renderze

1. Rozpakuj ZIP i utwórz nowe repozytorium GitHub. Wgraj zawartość katalogu aplikacji, w tym `app.py`, `requirements.txt`, `render.yaml`, `templates/` oraz `static/`. Sam plik `app.py` nie wystarcza.
2. Przygotuj trwałą bazę PostgreSQL, np. Neon, i skopiuj jej adres połączenia. Dane kont, pomysłów, wydarzeń, poczty i plików są zapisywane w tej bazie. Nie używaj SQLite na nietrwałym dysku Rendera.
3. Na Renderze utwórz usługę z pliku `render.yaml` (Blueprint) połączoną z repozytorium. Alternatywnie utwórz Python Web Service: polecenie budowania `pip install -r requirements.txt`, polecenie startowe `gunicorn app:app`.
4. Ustaw zmienne środowiskowe:

| Zmienna | Wartość |
| --- | --- |
| `DATABASE_URL` | Adres PostgreSQL od dostawcy bazy, wraz z wymaganymi parametrami SSL |
| `SECRET_KEY` | Długi losowy sekret, stały pomiędzy wdrożeniami; Blueprint generuje go automatycznie |
| `ADMIN_LOGIN` | Wybrany login pierwszego administratora |
| `ADMIN_PASSWORD` | Wybrane hasło co najmniej 10 znaków |
| `COOKIE_SECURE` | `1` na Renderze z HTTPS |

5. Uruchom wdrożenie. Pierwsze konto administratora tworzy się automatycznie tylko wtedy, gdy tabela użytkowników jest pusta. Zaloguj się podanym loginem i hasłem.
6. W panelu „Użytkownicy” dodaj opiekunów. Uczniów może dodawać administrator albo opiekun w „Składzie trójki”.

Zmiana `ADMIN_PASSWORD` w ustawieniach Rendera po utworzeniu konta nie resetuje jego hasła. Do tego służy profil lub panel innego administratora. Hasła nie są wyświetlane i są przechowywane jako bezpieczne skróty. Reset hasła unieważnia wcześniejsze sesje.

Przy przenoszeniu danych wykonuj kopię całej bazy, która zawiera także załączniki. Usunięcie konta pozostawia dotychczasowe wiadomości u innych osób; autor jest oznaczony jako „Usunięte konto”.

## Uruchomienie lokalne

Wymagany Python 3.11 lub nowszy. Zainstaluj `requirements.txt`, ustaw `SECRET_KEY`, `ADMIN_LOGIN`, `ADMIN_PASSWORD` i uruchom `python app.py`. Otwórz `http://127.0.0.1:5000`. Bez `DATABASE_URL` aplikacja korzysta z lokalnego `portal.db`. Lokalnie nie ustawiaj `COOKIE_SECURE=1`, jeżeli używasz HTTP. Do pracy wielu osób używaj wdrożenia z PostgreSQL i HTTPS.

## Weryfikacja wersji

Automatyczne testy klientem Flask obejmowały renderowanie ekranów, uprawnienia ról, wydarzenia, prywatność pomysłów, wiadomości z PDF i zdjęciem, autoryzację pobierania, zawieszanie i odwieszanie, reset hasła, tworzenie i usuwanie kont oraz ochronę CSRF. Testy zakończyły się powodzeniem na SQLite. Nie wykonano wdrożenia do Twojego Rendera ani testu z Twoją bazą PostgreSQL. Wygląd nie został sprawdzony w przeglądarce.
