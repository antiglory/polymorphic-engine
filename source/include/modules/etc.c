#pragma once

void cprintf(const char* cp_stp, ...)
{
    va_list cp_args;
    va_start(cp_args, cp_stp);

    for (int c = 0; cp_stp[c] != '\0'; c++) {
        if (cp_stp[c] == '*')
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[1;33m*\033[0m");
            else
                putchar('*');
        else if (cp_stp[c] == '+')
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[1;36m+\033[0m");
            else
                putchar('+');
        else if (cp_stp[c] == '~')
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[1;35m~\033[0m");
            else
                putchar('~');
        else if (cp_stp[c] == '!')
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[1;31m!\033[0m");
            else
                putchar('!');
        else if (cp_stp[c] == '=')
            if (cp_stp[c-1] == '[' && cp_stp[c+1] == ']')
                printf("\033[1;35m=\033[0m");
            else
                putchar('=');
        else if (cp_stp[c] == '%') {
            if (cp_stp[c+1] == 'd') {
                int32_t cp_val = va_arg(cp_args, int32_t);

                printf("%d", cp_val);

                c += 1;
            } else if (cp_stp[c+1] == 's') {
                char cp_val = va_arg(cp_args, char);

                printf("%s", cp_val);

                c += 1;
            } else if (cp_stp[c+1] == 'z') {
                if (cp_stp[c+2] == 'u') {
                    size_t cp_val = va_arg(cp_args, size_t);

                    printf("%zu", cp_val);

                    c += 2;
                } else if (cp_stp[c+2] == 'd') {
                    ssize_t cp_val = va_arg(cp_args, ssize_t);

                    printf("%zd", cp_val);

                    c += 2;
                } else
                    putchar('%');
            } else if (cp_stp[c+1] == 'p') {
                void* cp_val = va_arg(cp_args, void*);

                printf("\033[0;32m%p\033[0m", cp_val);

                c += 1;
            } else if (cp_stp[c+1] == 'l') {
                if (cp_stp[c+2] == 'x') {
                    unsigned long cp_val = va_arg(cp_args, unsigned long);

                    printf("\033[0;32m%lx\033[0m", cp_val);

                    c += 2;
                } else
                    putchar('%');
            } else
                putchar('%');
        } else
            putchar(cp_stp[c]);
    }

    va_end(cp_args);
}