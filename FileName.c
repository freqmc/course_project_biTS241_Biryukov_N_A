#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

//��������� ��� ������ �������� �� ���-�����
typedef struct {
    int cpu_load;
    int ram_load;
    int disk_load;
} input_values;

//��������� ��������� ��������
typedef struct {
    int cpu_limit;
    int ram_limit; 
    int disk_limit; 
} thresholds;

thresholds set_check_values(); 
int check_threat_level(input_values values, thresholds limits); 
void read_from_log_file(const wchar_t* filename, thresholds limits); 

int main() {
    setlocale(LC_CTYPE, ""); // ��������� ������
    wchar_t filename[256];
    int choice;

    thresholds limits = { 0, 0, 0 }; // ������������� ���������� ��� �������

    do {
        printf("�������� ����������� �������:\n");
        printf("1) ������� ��������� ��������\n");
        printf("2) ������ ���-�����\n");
        printf("��� ������ �� ��������� ������� �� 0\n");
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            limits = set_check_values();
            break;
        case 2:
            printf("������� ��� ���-����� ��� �������: ");
            wscanf(L"%ls", filename);
            read_from_log_file(filename, limits);
            break;
        case 0:
            break;
        default:
            printf("��� ����� �������.\n");
        }
    } while (choice != 0);
    return 0;
}

thresholds set_check_values() {
    thresholds thresholds;
    printf("������� ��������� �������� ��� �������� ���������� (0-100): ");
    scanf("%d", &thresholds.cpu_limit);
    printf("������� ��������� �������� ��� �������� ����������� ������ (0-100): ");
    scanf("%d", &thresholds.ram_limit);
    printf("������� ��������� �������� ��� �������� ��������� ������������ (0-100): ");
    scanf("%d", &thresholds.disk_limit);
    printf("��������� �������� �����������.\n");
    return thresholds; // ���������� ��������� ��������
}

int check_threat_level(input_values values, thresholds limits) {
    int below_threshold = 0;

    // ���������, ������� �������� ���� �������� �������
    if (values.cpu_load < limits.cpu_limit) {
        below_threshold++;
    }
    if (values.ram_load < limits.ram_limit) {
        below_threshold++;
    }
    if (values.disk_load < limits.disk_limit) {
        below_threshold++;
    }

    // ���������� ������� ������
    return below_threshold;
}

void read_from_log_file(const wchar_t* filename, thresholds limits) { // �������� ������� � ���� ���������
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("�� ������� ������� ����");
        exit(EXIT_FAILURE);
    }

    input_values values;
    wchar_t line[256]; // ����� ��� ������
    wchar_t threats[100][256]; // ������ ����� ��� ����� (�� ����� 100 �������)
    int threats_count = 0; // ������� �����

    // ��������� ������ �� �����
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        // �������� ��������
        values.cpu_load = -1;
        values.ram_load = -1;
        values.disk_load = -1;

        // ������������ ������
        wchar_t* cpu_str = wcsstr(line, L"�������� ����������");
        wchar_t* ram_str = wcsstr(line, L"�������� ����������� ������");
        wchar_t* disk_str = wcsstr(line, L"�������� ��������� ������������");

        // ���� ������� ��������, ��������� ��
        if (cpu_str) {
            swscanf(cpu_str, L"�������� ���������� = %d%%", &values.cpu_load);
        }
        if (ram_str) {
            swscanf(ram_str, L"�������� ����������� ������ = %d%%", &values.ram_load);
        }
        if (disk_str) {
            swscanf(disk_str, L"�������� ��������� ������������ = %d%%", &values.disk_load);
        }

        // �������� ������� ������
        int below_threshold = check_threat_level(values, limits); // �������� ������

        // ��������� �������� ������
        if (below_threshold > 0) {
            wchar_t threat_level[20];
            switch (below_threshold) {
            case 3:
                wcscpy(threat_level, L"�������");
                break;
            case 2:
                wcscpy(threat_level, L"�������");
                break;
            case 1:
                wcscpy(threat_level, L"������");
                break;
            default:
                continue; // ���������� ���������, ����������
            }

            swprintf(threats[threats_count++], 256, L"������� ������: %ls, �������� ����������: %d%%, �������� ����������� ������: %d%%, �������� ��������� ������������: %d%%\n",
                threat_level, values.cpu_load, values.ram_load, values.disk_load);
        }
    }

    fclose(log_file);

    // ���� ���� ������, ��������� ������������ ������� ������� ��� ����������
    if (threats_count > 0) {
        printf("�������� ������� ����� ��� ����������:\n");
        printf("1) �������\n");
        printf("2) �������\n");
        printf("3) ������\n");
        printf("������� ����� ������ (0 ��� ������): ");
        int chosen_level;
        scanf("%d", &chosen_level);

        // ������ �� ���������� � ����
        if (chosen_level > 0 && chosen_level <= 3) {
            wchar_t output_filename[256];
            printf("������� ��� ����� ��� ����������: ");
            wscanf(L"%ls", output_filename);
            FILE* output_file = _wfopen(output_filename, L"w, ccs=UTF-8");
            if (!output_file) {
                perror("�� ������� ������� ���� ��� ������");
                exit(EXIT_FAILURE);
            }

            // ������ ����� � ����
            for (int i = 0; i < threats_count; i++) {
                if ((chosen_level == 1 && wcsstr(threats[i], L"�������")) ||
                    (chosen_level == 2 && wcsstr(threats[i], L"�������")) ||
                    (chosen_level == 3 && wcsstr(threats[i], L"������"))) {
                    fputws(threats[i], output_file);
                }
            }

            fclose(output_file);
            wprintf(L"����� ������� �������� � ���� '%ls'.\n", output_filename);
        }
        else {
            wprintf(L"����� ��� ����������.\n");
        }
    }
    else {
        wprintf(L"�� ������� ������� ������ �� �����. ���������, ��� ������ ���������� ��� ������ �����������.\n");
    }
}