# Authentication-best-practice

Progetto che espone le best practice per implementare un sistema di autenticazione sicuro basato su token JWT. 
L’architettura iniziale è stata generata con l’ausilio di agenti LLM.
In seguito, sono riportate le specifiche utilizzate per la generazione di questo sistema (non si tratta di quelle originali, ma di un riassunto degli aspetti presi in considerazione).

## Gestione delle Password

- Le password devono avere almeno 8 caratteri.
- È consigliato applicare controlli di complessità (evitare sequenze banali).
- Non è necessario imporre obbligatoriamente caratteri speciali.
- Le password **non devono mai essere salvate in chiaro**.
- Devono essere memorizzate tramite algoritmi di hashing non reversibili.
- Utilizzare algoritmi sicuri e lenti come **bcrypt** o **Argon2**.
- La scelta dell’algoritmo è critica e difficile da modificare successivamente.
- Un hashing più lento aumenta la sicurezza ma introduce latenza.

## Salt

- Ogni password deve avere un **salt univoco** (stringa casuale).
- Il salt garantisce hash diversi anche per password identiche.
- È fondamentale per prevenire attacchi brute force e rainbow table.

## Sicurezza lato utente

- L’utente rappresenta spesso l’anello più debole.
- Dopo tentativi di login falliti:
  - applicare timeout progressivi,
  - utilizzare CAPTCHA,
  - richiedere verifiche aggiuntive (es. email).
- Tutte le comunicazioni devono avvenire tramite **HTTPS**.

## Processo di Autenticazione

- Il server confronta l’hash della password inserita con quello salvato.
- Non fornire mai informazioni specifiche su username o password errati.
- Dopo l’autenticazione:
  - generare un ID di sessione sicuro (≥128 bit) tramite CSPRNG,
  - gestire correttamente il cookie di sessione.

## Gestione Sessione e Cookie

- I cookie devono:
  - essere trasmessi solo su HTTPS,
  - non essere accessibili via JavaScript (HttpOnly),
  - essere protetti da richieste cross-site (SameSite).
- Le sessioni devono avere una scadenza (timeout).
- Logout e reset password devono invalidare sessione e cookie.

## Recupero Password e Sicurezza Avanzata

- Il reset password deve essere trattato come un processo separato.
- Implementare, quando possibile, la **Multi-Factor Authentication (MFA)**:
  - token fisici,
  - app di autenticazione,
  - SMS (meno sicuro ma ampiamente utilizzato).
