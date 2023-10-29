#include <iostream>
#include <string>
#include <ncurses.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <atomic>
#include <thread>
#include <pcap.h>

//用于暂停和继续
std::atomic<bool> process(true);
//必要的变量
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;

std::string select_interface(){
    pcap_if_t *alldevs, *d;
    int i=0;
    // 获取可用的网络接口列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s\n", ++i, d->name);
    }

    if (i == 0) {
        printf("No interfaces found! Exiting...\n");
        exit(1);
    }

    printf("Enter the interface number (1-%d): ", i);
    int interface_choice;
    scanf("%d", &interface_choice);

    if (interface_choice < 1 || interface_choice > i) {
        printf("Invalid choice! Exiting...\n");
        exit(1);
    }

    // 打开选择的接口
    d = alldevs;
    for (i = 0; i < interface_choice - 1; d = d->next, i++);
    std::string ret((char*)(d->name));
    return ret;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    //是否对数据包进行进一步的加工由主程序决定
    if(process){
        printf("Packet captured with length: %d\r\n", pkthdr->len);
    }
}

void pacp_start(){
    pcap_loop(handle,0,packet_handler,NULL);
}
void capwindow(char* interface){
    // 打开网络接口以捕获数据包
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\r\n", errbuf);
        exit(1);
    }

    initscr(); // 初始化ncurses
    cbreak();  // 立即响应输入，但不处理特殊控制字符
    noecho();  // 禁用回显
    nodelay(stdscr, TRUE); // 设置非阻塞输入

    std::thread task(pacp_start);
    
    int ch;
    bool flag=true;
    while (flag) {
        ch = getch();
        switch (ch){
        case 'b':
            process = false;
            printw("break\r\n");
            break;

        case 'c':
            process = true;
            printw("continue\r\n");
            break;

        case 's':
            printw("save\r\n");
            break;

        case 'q':
            printw("quit\r\n");
            // 关闭捕获会话
            pcap_close(handle);
            flag=false;
            break;
        default:
            break;
        }
        sleep(0.5);
    }
    task.join();
    endwin(); // 结束ncurses
}

int main() {
    char input;
    while(1){
        std::string interface=select_interface();
        capwindow((char*)&interface[0]);
        scanf("%*[^\n]"); scanf("%*c");
        printf("Quit?[y/other]\n");
        scanf("%c",&input);
        scanf("%*[^\n]"); scanf("%*c");
        if(input=='y'){
            printf("Quit!\n");
            break;
        }
    }
    return 0;
}

