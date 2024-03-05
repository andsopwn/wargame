// g++ -o main main.cpp

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <thread>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

#define CMD_MINING                  1
#define CMD_SHOW_MINERAL_BOOK       2
#define CMD_EDIT_MINERAL_BOOK       3
#define CMD_EXIT                    4

#define MAX_DESCRIPTION_SIZE 0x10

typedef void (*DESC_FUNC)(void);

/* Initialization */

void get_shell()
{
    system("/bin/sh");
}

void alarm_handler(int trash)
{
    std::cout << "TIME OUT" << std::endl;
    exit(-1);
}

void __attribute__((constructor)) initialize(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(60);
}

/* Print functions */

void print_banner()
{
    std::cout << "I love minerals!" << std::endl;
}

void print_menu()
{
    std::cout << std::endl << "[Menu]" << std::endl;
    std::cout << "1. Mining" << std::endl;
    std::cout << "2. Show mineral book" << std::endl;
    std::cout << "3. Edit mineral book" << std::endl;
    std::cout << "4. Exit program" << std::endl;
}

void print_scandium_description()
{
    std::cout << "Name        : Scandium" << std::endl;
    std::cout << "Symbol      : Sc" << std::endl;
    std::cout << "Description : A silvery-white metallic d-block element" << std::endl;
}

void print_yttrium_description()
{
    std::cout << "Name        : Yttrium" << std::endl;
    std::cout << "Symbol      : Y" << std::endl;
    std::cout << "Description : A silvery-metallic transition metal chemically similar to the lanthanides" << std::endl;
}

void print_lanthanum_description()
{
    std::cout << "Name        : Lanthanum" << std::endl;
    std::cout << "Symbol      : La" << std::endl;
    std::cout << "Description : A soft, ductile, silvery-white metal that tarnishes slowly when exposed to air" << std::endl;
}

void print_cerium_description()
{
    std::cout << "Name        : Cerium" << std::endl;
    std::cout << "Symbol      : Ce" << std::endl;
    std::cout << "Description : A soft, ductile, and silvery-white metal that tarnishes when exposed to air" << std::endl;
}

void print_praseodymium_description()
{
    std::cout << "Name        : Praseodymium" << std::endl;
    std::cout << "Symbol      : Pr" << std::endl;
    std::cout << "Description : A soft, silvery, malleable and ductile metal, valued for its magnetic, electrical, chemical, and optical properties" << std::endl;
}

std::vector<DESC_FUNC> rare_earth_description_funcs = {
    print_scandium_description,
    print_yttrium_description,
    print_lanthanum_description,
    print_cerium_description,
    print_praseodymium_description
};

/* Utils */

int get_int(const char* prompt = ">> ")
{
    std::cout << prompt;

    int x;
    std::cin >> x;
    return x;
}

std::string get_string(const char* prompt = ">> ")
{
    std::cout << prompt;

    std::string x;
    std::cin >> x;
    return x;
}

int get_rand_int(int start, int end)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(start, end);

    return dis(gen);
}

/* Classes */

class Mineral 
{
public:
    virtual void print_description() const = 0;
};

class UndiscoveredMineral : public Mineral
{
public:
    UndiscoveredMineral(std::string description_)
    {
        strncpy(description, description_.c_str(), MAX_DESCRIPTION_SIZE);
    }

    void print_description() const override 
    {
        std::cout << "Name        : Unknown" << std::endl;
        std::cout << "Symbol      : Un" << std::endl;
        std::cout << "Description : " << description << std::endl;
    }

    char description[MAX_DESCRIPTION_SIZE];
};

class RareEarth : public Mineral
{
public:
    RareEarth(DESC_FUNC description_)
    : description(description_)
    {

    }

    void print_description() const override 
    {
        if ( description )
            description();
    }

    DESC_FUNC description;   
};

/* Action functions */

std::vector<Mineral *> minerals;

void mining()
{
    std::cout << "[+] Mining..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(get_rand_int(100, 1000)));

    if ( get_rand_int(1, 100) <= 50 )
    {
        std::cout << "[+] Congratulations! you found an *undiscovered* mineral!" << std::endl;
        
        std::string description = get_string("Please enter mineral's description : ");
        minerals.push_back(new UndiscoveredMineral(description));
    }

    else if ( get_rand_int(1, 100) <= 5 )
    {
        std::cout << "[+] You found a rare-earth element!" << std::endl;
        
        DESC_FUNC description = rare_earth_description_funcs[get_rand_int(0, rare_earth_description_funcs.size() - 1)];
        minerals.push_back(new RareEarth(description));
        minerals.back()->print_description();
    }

    else {
        std::cout << "[!] Found nothing" << std::endl;
    }
        
    return;
}

void edit_mineral_book()
{
    int index = get_int("[?] Index : ");

    if ( index < 0 || index >= minerals.size() )
    {
        std::cout << "[!] Invalid index" << std::endl;
        return;
    }

    std::string description = get_string("Please enter mineral's description : ");
    strncpy(
        static_cast<UndiscoveredMineral*>(minerals[index])->description,
        description.c_str(),
        MAX_DESCRIPTION_SIZE
    );
}

void show_mineral_book()
{
    for ( int index = 0; index < minerals.size(); index++ )
    {
        std::cout << "--------------------" << std::endl;
        std::cout << "Index       : " << index << std::endl;
        minerals[index]->print_description();
    }

    std::cout << std::endl;
}
 
/* Main function */

int main(){
    print_banner();

    while(1){
        print_menu();

        int selector = get_int();

        switch (selector){
            case CMD_MINING:
                mining();
                break;

            case CMD_SHOW_MINERAL_BOOK:
                show_mineral_book();
                break;

            case CMD_EDIT_MINERAL_BOOK:
                edit_mineral_book();
                break;

            case CMD_EXIT:
                return 0;

            default:
                std::cout << "[!] You select wrong number!" << std::endl;
                break;
        }
    }
    return 0;    
}