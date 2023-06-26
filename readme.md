# JWT-Security

In diesem Projekt habe ich JWT-Security mit Spring Boot ausprobiert. 

Die Anwendung erstellt für einen Nutzer mit korrekten Logindaten einen JWT-Token mit 15-minütiger Gültigkeit.
Für eingeloggte Nutzer ist es möglich auf Daten zuzugreifen und neue Nutzer zu erstellen.
Ist der Token eines Nutzers beim Zugriff auf Daten älter als 5 Minuten, so wird ein neuer Token mit 15-minütiger Gültigkeit erstellt und der alte auf eine Blacklist gesetzt.
Loggt sich der Nutzer aus, so wird der Token ebenfalls auf die Blacklist gesetzt und kann nicht mehr verwendet werden.
Die Blacklist wird bei jedem Zugriff von abgelaufenen Token gereinigt.