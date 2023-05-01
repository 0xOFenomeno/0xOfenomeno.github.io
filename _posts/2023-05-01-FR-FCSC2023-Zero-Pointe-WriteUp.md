---
title: FCSC 2023 - Misc - Zéro pointé- Writeup - FR
published: true
---


# [](#Introduction)Introduction

Bonjour à tous, cette semaine se déroulait la FCSC (France Cybersecurity Challenge) 2023, n'ayant pas eu le temps de me concentrer à 100% sur le CTF, j'ai néanmoins eu du temps libre pour réaliser quelques challenges dont le dénommé **Zéro pointé** dans la catégorie misc.


# [](#Contexte)Contexte

Ce challenge nous fournissait deux fichiers, un exécutable `zero-pointe` et un fichier C `zero-pointe.c`.

Voici le code C fourni:

```c
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


static void
flag(int sig)
{
    (void) sig;
    char flag[128];

    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    int n = read(fd, flag, sizeof(flag));
    if (n == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    flag[n] = 0;
    flag[strstr(flag, "\n") - flag] = 0;

    if (close(fd) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    printf("%s\n", flag);

    exit(EXIT_SUCCESS);
}

long
read_long()
{
    long val;
    scanf("%ld", &val);
    return val;
}

int
main()
{
    long a;
    long b;
    long c;

    if (signal(SIGFPE, flag) == SIG_ERR) {
        perror("signal");
        exit(EXIT_FAILURE);
    }

    a = read_long();
    b = read_long();
    c = b ? a / b : 0;

    printf("%ld\n", c);
    exit(EXIT_SUCCESS);
}
```


Ce programme est composé de 3 fonctions:
- La fonction `flag` permettant de lire et d'afficher le flag.
- la fonction `read_long` permettant de lire un entier long en entrée de clavier et de le retourner
- et la fonction `main` qui est la fonction principale de notre programme et celle qui nous intéresse le + dans le cadre de ce challenge.


## [](#Main)La fonction main

```c
int
main()
{
    long a;
    long b;
    long c;

    if (signal(SIGFPE, flag) == SIG_ERR) {
        perror("signal");
        exit(EXIT_FAILURE);
    }

    a = read_long();
    b = read_long();
    c = b ? a / b : 0;

    printf("%ld\n", c);
    exit(EXIT_SUCCESS);
}
```

La fonction `main` fait appel à la fonction `flag` que si le signal **SIGFPE**, synonyme d'exception arithmétique, est déclenché. Compte tenu du code, ce signal ne peut être déclenché que par les entiers longs ***a*** et ***b*** saisis par l'utilisateur. 

### [](#Hyp-1)Première hypothèse

La première hypothèse est le déclenchement du fameux signal SIGFPE via la division par 0, or la ligne

```c
c = b ? a / b : 0;
```
empêche la division par 0 puisque elle affecte à la variable ***c*** la valeur de la division **a/b** que si ***b*** ne vaut pas 0. Si ***b*** vaut 0, alors la valeur 0 est directment assignée à la variable ***c*** pour éviter la division par... 0 (oui ça fait beaucoup de zéros effectivement).


L'hypothèse de la division par 0 tombe donc à l'eau.


### [](#Hyp-2)Deuxième hypothèse

La deuxième hypothèse est celle de l'Integer Overflow avec une division négative, donc de saisir pour au moins l'un des deux entiers longs, une valeur non représentable par l'espace mémoire alloué.


Pour cela, j'ai utilisé ce petit programe me permettant de connaître l'entier long maximum pouvant être stocké par la mémoire.

```c
#include <stdio.h>
#include <limits.h>

int main()
{
printf("Long max: %ld\n", LONG_MAX);
return 0;
}
```

qui m'a retourné la valeur suivante: **9223372036854775807**

Suite à cela, j'ai essayé de récupérer le flag avec les entiers négatifs longs suivants:
- a = -9223372036854775808
- b = -1

et...


```bash
ofenomeno@pcofenomeno:~/Documents/fcsc/misc/zero$ nc challenges.france-cybersecurity-challenge.fr 2050
-9223372036854775808
-1
FCSC{0366ff5c59934da7301c0fc6cf7d617c99ad6f758831b1dc70378e59d1e060bf}
```

Nous récupérons le flag!



# [](#Conclusion) Conclusion

N'hésitez pas à me contacter sur Discord **Ofenomeno#3152** si vous avez des questions! Et bonne chance aux participants sélectionnés pour la prochaine étape de la FCSC! :)

