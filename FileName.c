#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

//Структура для записи значений из лог-файла
typedef struct {
    int cpu_load;
    int ram_load;
    int disk_load;
} input_values;

//Структура пороговых значений
typedef struct {
    int cpu_limit;
    int ram_limit; 
    int disk_limit; 
} thresholds;

thresholds set_check_values(); 
int check_threat_level(input_values values, thresholds limits); 
void read_from_log_file(const wchar_t* filename, thresholds limits); 

int main() {
    setlocale(LC_CTYPE, ""); // Установка локали
    wchar_t filename[256];
    int choice;

    thresholds limits = { 0, 0, 0 }; // Инициализация переменной для порогов

    do {
        printf("Выберите необходимую функцию:\n");
        printf("1) Указать пороговые значения\n");
        printf("2) Анализ лог-файла\n");
        printf("Для выхода из программы нажмите на 0\n");
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            limits = set_check_values();
            break;
        case 2:
            printf("Введите имя лог-файла для анализа: ");
            wscanf(L"%ls", filename);
            read_from_log_file(filename, limits);
            break;
        case 0:
            break;
        default:
            printf("Нет такой функции.\n");
        }
    } while (choice != 0);
    return 0;
}

thresholds set_check_values() {
    thresholds thresholds;
    printf("Введите пороговое значение для загрузки процессора (0-100): ");
    scanf("%d", &thresholds.cpu_limit);
    printf("Введите пороговое значение для загрузки оперативной памяти (0-100): ");
    scanf("%d", &thresholds.ram_limit);
    printf("Введите пороговое значение для загрузки дискового пространства (0-100): ");
    scanf("%d", &thresholds.disk_limit);
    printf("Пороговые значения установлены.\n");
    return thresholds; // Возвращаем пороговые значения
}

int check_threat_level(input_values values, thresholds limits) {
    int below_threshold = 0;

    // Проверяем, сколько значений ниже заданных порогов
    if (values.cpu_load < limits.cpu_limit) {
        below_threshold++;
    }
    if (values.ram_load < limits.ram_limit) {
        below_threshold++;
    }
    if (values.disk_load < limits.disk_limit) {
        below_threshold++;
    }

    // Определяем уровень угрозы
    return below_threshold;
}

void read_from_log_file(const wchar_t* filename, thresholds limits) { // Получаем пределы в виде параметра
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("Не удалось открыть файл");
        exit(EXIT_FAILURE);
    }

    input_values values;
    wchar_t line[256]; // Буфер для строки
    wchar_t threats[100][256]; // Массив строк для угроз (не более 100 записей)
    int threats_count = 0; // Счетчик угроз

    // Считываем строки из файла
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        // Обнуляем значения
        values.cpu_load = -1;
        values.ram_load = -1;
        values.disk_load = -1;

        // Обрабатываем строки
        wchar_t* cpu_str = wcsstr(line, L"Загрузка процессора");
        wchar_t* ram_str = wcsstr(line, L"Загрузка оперативной памяти");
        wchar_t* disk_str = wcsstr(line, L"Загрузка дискового пространства");

        // Если найдены значения, извлекаем их
        if (cpu_str) {
            swscanf(cpu_str, L"Загрузка процессора = %d%%", &values.cpu_load);
        }
        if (ram_str) {
            swscanf(ram_str, L"Загрузка оперативной памяти = %d%%", &values.ram_load);
        }
        if (disk_str) {
            swscanf(disk_str, L"Загрузка дискового пространства = %d%%", &values.disk_load);
        }

        // Получаем уровень угрозы
        int below_threshold = check_threat_level(values, limits); // Передаем пороги

        // Сохраняем описание угрозы
        if (below_threshold > 0) {
            wchar_t threat_level[20];
            switch (below_threshold) {
            case 3:
                wcscpy(threat_level, L"ВЫСОКИЙ");
                break;
            case 2:
                wcscpy(threat_level, L"СРЕДНИЙ");
                break;
            case 1:
                wcscpy(threat_level, L"НИЗКИЙ");
                break;
            default:
                continue; // Нормальное состояние, пропускаем
            }

            swprintf(threats[threats_count++], 256, L"Уровень угрозы: %ls, Загрузка процессора: %d%%, Загрузка оперативной памяти: %d%%, Загрузка дискового пространства: %d%%\n",
                threat_level, values.cpu_load, values.ram_load, values.disk_load);
        }
    }

    fclose(log_file);

    // Если есть угрозы, предложим пользователю выбрать уровень для сохранения
    if (threats_count > 0) {
        printf("Выберите уровень угроз для сохранения:\n");
        printf("1) ВЫСОКИЙ\n");
        printf("2) СРЕДНИЙ\n");
        printf("3) НИЗКИЙ\n");
        printf("Введите номер уровня (0 для выхода): ");
        int chosen_level;
        scanf("%d", &chosen_level);

        // Запрос на сохранение в файл
        if (chosen_level > 0 && chosen_level <= 3) {
            wchar_t output_filename[256];
            printf("Введите имя файла для сохранения: ");
            wscanf(L"%ls", output_filename);
            FILE* output_file = _wfopen(output_filename, L"w, ccs=UTF-8");
            if (!output_file) {
                perror("Не удалось открыть файл для записи");
                exit(EXIT_FAILURE);
            }

            // Запись угроз в файл
            for (int i = 0; i < threats_count; i++) {
                if ((chosen_level == 1 && wcsstr(threats[i], L"ВЫСОКИЙ")) ||
                    (chosen_level == 2 && wcsstr(threats[i], L"СРЕДНИЙ")) ||
                    (chosen_level == 3 && wcsstr(threats[i], L"НИЗКИЙ"))) {
                    fputws(threats[i], output_file);
                }
            }

            fclose(output_file);
            wprintf(L"Вывод успешно сохранен в файл '%ls'.\n", output_filename);
        }
        else {
            wprintf(L"Выход без сохранения.\n");
        }
    }
    else {
        wprintf(L"Не удалось считать данные из файла. Убедитесь, что формат правильный или данные отсутствуют.\n");
    }
}