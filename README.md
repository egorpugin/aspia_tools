# Aspia Tools

Состав
1. Обособленный роутер/релей 2-в-1

Сборка

1. Установить самую свежую Visual Studio.
2. Установить систему сборки sw https://software-network.org/client/
3. `git clone https://github.com/dchapyshev/aspia`
4. `sw -d aspia/source override org.sw.demo`
6. `cd aspia_tools`
7. `sw build -static`

Для создания решения VS
```sw generate -static```
