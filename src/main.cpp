#include <QApplication>
#include <QWidget>
#include <QListWidget>
#include <QListWidgetItem>
#include <QVBoxLayout>
#include <QTextBrowser>
#include <QLabel>
#include <QScrollArea>
#include <QPushButton>
#include <QDialog>
#include <QFileDialog>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <vector>
#include <iostream>
#include <string>
#include <stdio.h>
#include <thread>
#include <atomic>
#include <pcap.h>
#include <string.h>

QListWidget* packageListView;
int No;
int SelectedIndex;

//用于暂停和继续
std::atomic<bool> process(false);
//必要的变量
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
//用于保存数据包
std::vector<std::vector<u_char>> captured_packets;
std::vector<struct pcap_pkthdr> pkthdrs;
//用于正确打印时间戳
long int tv_usec0;
long int tv_sec0;

std::string package2String(const struct pcap_pkthdr *pkthdr, const u_char *packet){
    char ret[100]={'\0'};
    char temp[50]={'\0'};
    long int tv_sec = pkthdr->ts.tv_sec;
    long int tv_usec = pkthdr->ts.tv_usec;
    if (tv_sec0 == 0 && tv_usec0 == 0) {
        tv_sec0 = tv_sec;
        tv_usec0 = tv_usec;
    }
    if (tv_usec0 > tv_usec) {
        tv_sec -= 1;
        tv_usec += 1000000;
    }
    sprintf(temp,"%%1\t%ld.%06ld\t",tv_sec - tv_sec0, tv_usec - tv_usec0);
    strcat(ret,temp);
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    strcat(ret,inet_ntoa(ip_header->ip_src));
    sprintf(temp,"\t\t%s\t\t",inet_ntoa(ip_header->ip_dst));
    strcat(ret,temp);
    switch (ip_header->ip_p){
    case 1:
        sprintf(temp,"ICMP\t\t%d",pkthdr->len);
        break;
    case 6:
        sprintf(temp,"TCP\t\t%d",pkthdr->len);
        break;
    case 17:
        sprintf(temp,"UDP\t\t%d",pkthdr->len);
        break;
    default:
        break;
    }
    strcat(ret,temp);
    return std::string(ret);
}
std::string Frame2String(){
    char ret[1000]={'\0'};
    char temp[200]={'\0'};
    sprintf(temp,"-----------以太网帧-----------\n");
    strcat(ret,temp);
    const struct pcap_pkthdr *pkthdr = &pkthdrs[SelectedIndex];
    long int tv_sec = pkthdr->ts.tv_sec;
    long int tv_usec = pkthdr->ts.tv_usec;
    if (tv_sec0 == 0 && tv_usec0 == 0) {
        tv_sec0 = tv_sec;
        tv_usec0 = tv_usec;
    }
    if (tv_usec0 > tv_usec) {
        tv_sec -= 1;
        tv_usec += 1000000;
    }
    sprintf(temp,"Timestamp: %ld.%06ld seconds\n", tv_sec - tv_sec0, tv_usec - tv_usec0);
    strcat(ret,temp);

    sprintf(temp,"Packet Length: %d\n",pkthdr->len);
    strcat(ret,temp);

    // 解析以太网帧
    struct ether_header *eth_header = (struct ether_header *)&captured_packets[SelectedIndex][0];
    // 打印目标MAC地址
    sprintf(temp,"Destination MAC Address: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    strcat(ret,temp);
    // 打印源MAC地址
    sprintf(temp,"Source MAC Address: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    strcat(ret,temp);
    // 打印以太网帧类型或长度
    if (ntohs(eth_header->ether_type) <= 1500) {
        sprintf(temp,"Frame Length/Type: %u (IEEE 802.3 Ethernet)\n", ntohs(eth_header->ether_type));
        strcat(ret,temp);
    } else {
        if (ntohs(eth_header->ether_type) == 0x86dd) {
            sprintf(temp,"Frame Type: IPv6 (0x86dd)\n");
            strcat(ret,temp);
        } else if (ntohs(eth_header->ether_type) == 0x0800) {
            sprintf(temp,"Frame Type: IPv4 (0x0800)\n");
            strcat(ret,temp);
        } else {
            sprintf(temp,"Frame Type: Not support (0x%04x)\n", ntohs(eth_header->ether_type));
            strcat(ret,temp);
        }
    }
    return std::string(ret);
}

std::string IPH2String(){
    char ret[1000]={'\0'};
    char temp[200]={'\0'};

    sprintf(temp,"-----------IP数据报头-----------\n");
    strcat(ret,temp);
    // IPv4帧
    struct ip *ip_header = (struct ip *)(&captured_packets[SelectedIndex][0] + ETHER_HDR_LEN);
    // 打印第一部分：版本，首部长度，区分服务，总长度
    sprintf(temp,"Version: %d\n", ip_header->ip_v);
    strcat(ret,temp);
    sprintf(temp,"Header Length: %d bytes\n", ip_header->ip_hl * 4);
    strcat(ret,temp);
    sprintf(temp,"Differentiated Services: 0x%02X\n", ip_header->ip_tos);
    strcat(ret,temp);
    sprintf(temp,"Total Length: %d bytes\n", ntohs(ip_header->ip_len));
    strcat(ret,temp);

    // 打印第二部分：标识，标志，偏移
    sprintf(temp,"Identification: %d\n", ntohs(ip_header->ip_id));
    strcat(ret,temp);
    sprintf(temp,"Flags: %s %s %s\n",
           (ntohs(ip_header->ip_off) & IP_RF) ? "Reserved" : "",
           (ntohs(ip_header->ip_off) & IP_DF) ? "Don't Fragment" : "",
           (ntohs(ip_header->ip_off) & IP_MF) ? "More Fragments" : "");
    strcat(ret,temp);
    sprintf(temp,"Fragment Offset: %d\n", ntohs(ip_header->ip_off) & IP_OFFMASK);
    strcat(ret,temp);

    // 打印第三部分：生存时间，协议，首部校验和
    sprintf(temp,"Time to Live: %d\n", ip_header->ip_ttl);
    strcat(ret,temp);
    switch (ip_header->ip_p){
    case 1:
        sprintf(temp,"Protocol: ICMP (1)\n");
        strcat(ret,temp);
        break;
    case 6:
        sprintf(temp,"Protocol: TCP (6)\n");
        strcat(ret,temp);
        break;
    case 17:
        sprintf(temp,"Protocol: UDP (17)\n");
        strcat(ret,temp);
        break;
    default:
        sprintf(temp,"Protocol: Not support(%d)\n",ip_header->ip_p);
        strcat(ret,temp);
        break;
    }
    sprintf(temp,"Header Checksum: 0x%04X\n", ntohs(ip_header->ip_sum));
    strcat(ret,temp);

    // 打印第四部分：源地址，目的地址
    sprintf(temp,"Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    strcat(ret,temp);
    sprintf(temp,"Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    strcat(ret,temp);

    return std::string(ret);
}

std::string TCP2String(){
    char ret[1000]={'\0'};
    char temp[200]={'\0'};

    sprintf(temp,"-----------TCP报头-----------\n");
    strcat(ret,temp);
    const u_char *packet=&captured_packets[SelectedIndex][0];
    // 解析IP头部，获取首部长度，然后计算TCP头部的位置
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *tcp_packet = packet + ETHER_HDR_LEN + ip_header_len;

    struct tcphdr *tcp_header = (struct tcphdr *)(tcp_packet);

    sprintf(temp,"Source Port: %d\n", ntohs(tcp_header->th_sport));
    strcat(ret,temp);
    sprintf(temp,"Destination Port: %d\n", ntohs(tcp_header->th_dport));
    strcat(ret,temp);
    sprintf(temp,"Sequence Number: %u\n", ntohl(tcp_header->th_seq));
    strcat(ret,temp);
    sprintf(temp,"Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
    strcat(ret,temp);
    sprintf(temp,"Data Offset: %d bytes\n", tcp_header->th_off * 4);
    strcat(ret,temp);
    sprintf(temp,"Flags: ");
    strcat(ret,temp);
    if (tcp_header->th_flags & TH_FIN) sprintf(temp,"FIN "),strcat(ret,temp);
    if (tcp_header->th_flags & TH_SYN) sprintf(temp,"SYN "),strcat(ret,temp);
    if (tcp_header->th_flags & TH_RST) sprintf(temp,"RST "),strcat(ret,temp);
    if (tcp_header->th_flags & TH_PUSH) sprintf(temp,"PSH "),strcat(ret,temp);
    if (tcp_header->th_flags & TH_ACK) sprintf(temp,"ACK "),strcat(ret,temp);
    if (tcp_header->th_flags & TH_URG) sprintf(temp,"URG "),strcat(ret,temp);
    sprintf(temp,"\n");
    strcat(ret,temp);
    sprintf(temp,"Window Size: %d\n", ntohs(tcp_header->th_win));
    strcat(ret,temp);
    sprintf(temp,"Checksum: 0x%04X\n", ntohs(tcp_header->th_sum));
    strcat(ret,temp);
    sprintf(temp,"Urgent Pointer: %d\n", ntohs(tcp_header->th_urp));
    strcat(ret,temp);
    return std::string(ret);
}

std::string UDP2String(){
    char ret[1000]={'\0'};
    char temp[200]={'\0'};

    sprintf(temp,"-----------UDP报头-----------\n");
    strcat(ret,temp);
    
    // 解析IP头部，获取首部长度，然后计算UDP头部的位置
    const u_char *packet=&captured_packets[SelectedIndex][0];
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *udp_packet = packet + ETHER_HDR_LEN + ip_header_len;

    struct udphdr *udp_header = (struct udphdr *)(udp_packet);

    sprintf(temp,"Source Port: %d\n", ntohs(udp_header->uh_sport));
    strcat(ret,temp);
    sprintf(temp,"Destination Port: %d\n", ntohs(udp_header->uh_dport));
    strcat(ret,temp);
    sprintf(temp,"Length: %d bytes\n", ntohs(udp_header->uh_ulen));
    strcat(ret,temp);
    sprintf(temp,"Checksum: 0x%04X\n", ntohs(udp_header->uh_sum));
    strcat(ret,temp);

    return std::string(ret);
}

std::string ICMP2String(){
    char ret[1000]={'\0'};
    char temp[200]={'\0'};

    sprintf(temp,"-----------ICMP数据报-----------\n");
    strcat(ret,temp);
    
    // 解析IP头部，获取首部长度，然后计算ICMP数据报的位置
    const u_char *packet=&captured_packets[SelectedIndex][0];
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *icmp_packet = packet + ETHER_HDR_LEN + ip_header_len;

    // ICMP头部没有特定的结构，您可以根据需要解析各个字段
    // 下面只是一个示例，解析了类型和代码字段
    sprintf(temp,"Type: %d\n", icmp_packet[0]);
    strcat(ret,temp);
    sprintf(temp,"Code: %d\n", icmp_packet[1]);
    strcat(ret,temp);
    sprintf(temp,"Checksum: 0x%04X\n", ntohs(*(uint16_t *)(icmp_packet + 2)));
    strcat(ret,temp);
    
    return std::string(ret);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    //是否对数据包进行进一步的加工由主程序决定
    if(process){
        struct ether_header *eth_header = (struct ether_header *)packet;
        int ether_type=ntohs(eth_header->ether_type);
        if(!(ether_type==0x86dd||ether_type==0x0800)){
        }else if(ether_type==0x0800){
            struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
            int protocol=ip_header->ip_p;
            if(protocol==1||protocol==6||protocol==17){
                // 将捕获的数据包存储在Vector中
                std::vector<u_char> captured_packet(packet, packet + pkthdr->len);
                pkthdrs.push_back(*pkthdr);
                captured_packets.push_back(captured_packet);
                QString newItem = QString(&package2String(pkthdr,packet)[0]).arg(No);
                QListWidgetItem* listItem = new QListWidgetItem(newItem);
                listItem->setData(Qt::UserRole, QVariant(No-1));
                packageListView->addItem(listItem);
                No++;
            }
        }
    }
}

void pacp_start(){
    pcap_loop(handle,0,packet_handler,NULL);
}

std::vector<std::string> getInterfaces(){
    pcap_if_t *alldevs, *d;
    std::vector<std::string> ret;
    int i=0;
    // 获取可用的网络接口列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding network devices: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d; d = d->next,i++) {
        ret.push_back(d->name);
    }

    if (i == 0) {
        printf("No interfaces found! Exiting...\n");
        exit(1);
    }
    return ret;
}

void savepacp(pcap_t *handle,const char *fname){
    pcap_dumper_t *pcap_dumper = NULL;
    // 打开一个用于保存pcap文件的文件
    pcap_dumper = pcap_dump_open(handle,fname);
    if(pcap_dumper==nullptr){
        printf("Can not open pcapfile\n");
        return;
    }
    // 写入文件
    for(int i=0;i<pkthdrs.size();++i){
        pcap_dump((u_char *)pcap_dumper, &pkthdrs[i], &captured_packets[i][0]);
    }
    // 关闭pcap文件
    if (pcap_dumper != NULL) {
        pcap_dump_close(pcap_dumper);
    }
}

int HasIPHead(){
    struct ether_header *eth_header = (struct ether_header *)&captured_packets[SelectedIndex][0];
    int ether_type=ntohs(eth_header->ether_type);
    if(!(ether_type==0x86dd||ether_type==0x0800)){
    }else if(ether_type==0x0800){
        return 1;
    }
    return 0;
}
int HasTUC(){
    struct ip *ip_header = (struct ip *)(&captured_packets[SelectedIndex][0] + ETHER_HDR_LEN);
    int protocol=ip_header->ip_p;
    if(protocol==1||protocol==6||protocol==17){
        return 1;
    }
    return 0;
}
std::string TUCHead(){
    struct ip *ip_header = (struct ip *)(&captured_packets[SelectedIndex][0] + ETHER_HDR_LEN);
    switch (ip_header->ip_p){
    case 1:
        return std::string("ICMP");
        break;
    case 6:
        return std::string("TCP");
        break;
    case 17:
        return std::string("UDP");
        break;
    default:
        return std::string("Un supported");
        break;
    }
}

void showSelected(QListWidget* selectedPackage){
    QString frameItem("Frame");
    QListWidgetItem* frame = new QListWidgetItem(frameItem);
    frame->setData(Qt::UserRole, QVariant("Frame"));
    selectedPackage->addItem(frame);
    if(HasIPHead()){
        QString ipItem("IPHead");
        QListWidgetItem* ipHead = new QListWidgetItem(ipItem);
        ipHead->setData(Qt::UserRole, QVariant("IPHead"));
        selectedPackage->addItem(ipHead);
        if(HasTUC()){
            const char* tuc=&TUCHead()[0];
            QString protocolItem = QString(tuc);
            QListWidgetItem* TUC = new QListWidgetItem(protocolItem);
            TUC->setData(Qt::UserRole, QVariant(tuc));
            selectedPackage->addItem(TUC);
        }
    }
}

class CaptureWindow : public QDialog {
public:
    CaptureWindow(QWidget* parent = nullptr, const QString& interface = "") : QDialog(parent) {
        setWindowTitle(interface);
        resize(1200, 800);
        // 创建一个垂直布局，将窗口分成上、下两个部分
        QVBoxLayout* captureLayout = new QVBoxLayout(this);
        // 上部分，背景色白色
        QWidget* topWidget = new QWidget(this);
        topWidget->setSizePolicy(QSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding));
        // 上部分，创建一个垂直布局
        QVBoxLayout* topLayout = new QVBoxLayout(topWidget);
        // 在上面创建一个用来存放按钮的组件
        QWidget* buttonWidget = new QWidget(topWidget);
        // 创建一个水平的布局
        QHBoxLayout* buttonLayout = new QHBoxLayout(buttonWidget);
        // 添加几个按钮
        QPushButton* pauseButton = new QPushButton("暂停");
        QPushButton* startButton = new QPushButton("开始");
        QPushButton* saveButton = new QPushButton("保存");
        buttonLayout->addWidget(pauseButton);
        buttonLayout->addWidget(startButton);
        buttonLayout->addWidget(saveButton);
        // 表头指示字段
        QLabel* tableHead = new QLabel(
"No.          时间                      源                                       目的                                    协议                     长度",
            topWidget
        );
        // 创建一个滚动区域，存放数据包
        QScrollArea* scrollArea = new QScrollArea;
        scrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        topLayout->addWidget(buttonWidget);
        topLayout->addWidget(tableHead);
        topLayout->addWidget(scrollArea);
        // 创建一个列表视图
        packageListView = new QListWidget;
        // 设置列表视图属性
        packageListView->setViewMode(QListWidget::ListMode);
        packageListView->setSelectionMode(QAbstractItemView::SingleSelection);
        No=1;
        // 设置滚动区域的内容视图为可伸缩
        scrollArea->setWidgetResizable(true);
        // 将列表视图添加到滚动区域
        scrollArea->setWidget(packageListView);
        // 设置背景色等
        QPalette topPalette = topWidget->palette();
        topPalette.setColor(QPalette::Window, Qt::white);
        topWidget->setAutoFillBackground(true);
        topWidget->setPalette(topPalette);
        captureLayout->addWidget(topWidget);

        // 下部分，背景色浅绿色，左右结构
        QWidget* bottomWidget = new QWidget(this);
        bottomWidget->setSizePolicy(QSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding));
        QHBoxLayout* bottomLayout = new QHBoxLayout(bottomWidget);

        // 左部分，背景色浅灰色
        QWidget* leftWidget = new QWidget(bottomWidget);
        QVBoxLayout* leftLayout = new QVBoxLayout(leftWidget);
        QListWidget* selectedPackage = new QListWidget;
        leftLayout->addWidget(selectedPackage);

        QPalette leftPalette = leftWidget->palette();
        leftPalette.setColor(QPalette::Window, Qt::lightGray);
        leftWidget->setAutoFillBackground(true);
        leftWidget->setPalette(leftPalette);

        // 右部分，背景色浅绿色
        QWidget* rightWidget = new QWidget(bottomWidget);
        QVBoxLayout* rightLayout = new QVBoxLayout(rightWidget);
        QTextBrowser* PackageMessage = new QTextBrowser;
        rightLayout->addWidget(PackageMessage);

        QPalette rightPalette = rightWidget->palette();
        rightPalette.setColor(QPalette::Window, QColor(173, 216, 230)); // 浅绿色
        rightWidget->setAutoFillBackground(true);
        rightWidget->setPalette(rightPalette);

        // 添加左右部分到底部布局
        bottomLayout->addWidget(leftWidget);
        bottomLayout->addWidget(rightWidget);
        captureLayout->addWidget(bottomWidget);
        // 为按钮关联函数
        connect(pauseButton, &QPushButton::clicked, [](){
            process = false;
        });
        connect(startButton, &QPushButton::clicked, [](){
            process = true;
        });
        connect(saveButton, &QPushButton::clicked, [parent](){
            parent->show();
            QString filePath = QFileDialog::getSaveFileName(nullptr,"选择文件", "", "所有文件 (*.*)");
            savepacp(handle,filePath.toUtf8().constData());
        });
        connect(packageListView,&QListWidget::itemClicked, [this,selectedPackage,PackageMessage](QListWidgetItem *item){
            selectedPackage->clear();
            PackageMessage->setPlainText("");
            SelectedIndex=item->data(Qt::UserRole).toInt();
            showSelected(selectedPackage);
        });
        connect(selectedPackage,&QListWidget::itemClicked, [this,PackageMessage](QListWidgetItem *item){
            const char* showType = item->data(Qt::UserRole).toString().toUtf8().constData();
            if(strcmp(showType,"Frame")==0){
                PackageMessage->setPlainText(&Frame2String()[0]);
            }else if(strcmp(showType,"IPHead")==0){
                PackageMessage->setPlainText(&IPH2String()[0]);
            }else if(strcmp(showType,"TCP")==0){
                PackageMessage->setPlainText(&TCP2String()[0]);
            }else if(strcmp(showType,"UDP")==0){
                PackageMessage->setPlainText(&UDP2String()[0]);
            }else if(strcmp(showType,"ICMP")==0){
                PackageMessage->setPlainText(&ICMP2String()[0]);
            }
        });
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    // 创建主窗口
    QWidget mainWindow;
    mainWindow.setWindowTitle("Interface Selection");
    mainWindow.resize(600, 800);

    // 创建一个垂直布局
    QVBoxLayout layout(&mainWindow);

    // 创建一个按钮并设置按钮文本
    QPushButton openFileButton("打开文件");

    // 添加按钮到布局
    layout.addWidget(&openFileButton);

    // 假设接口列表
    QStringList availableInterfaces;
    std::vector<std::string> interfaces=getInterfaces();
    for(int i=0;i<interfaces.size();++i){
        availableInterfaces << (char*)&interfaces[i][0];
    }
    // 创建一个列表视图
    QListWidget interfaceListView;

    // 设置列表视图属性
    interfaceListView.setViewMode(QListWidget::ListMode);
    interfaceListView.setSelectionMode(QAbstractItemView::SingleSelection);

    // 添加接口到列表
    foreach(const QString &interface, availableInterfaces) {
        QListWidgetItem *item = new QListWidgetItem(&interfaceListView);
        item->setData(Qt::UserRole, QVariant(interface)); // 存储接口名称
        QLabel *label = new QLabel(interface);
        label->setAlignment(Qt::AlignCenter); // 文本居中
        interfaceListView.setItemWidget(item, label);
    }

    // 将列表视图添加到布局
    layout.addWidget(&interfaceListView);

    // 连接信号和槽
    QObject::connect(&interfaceListView, &QListWidget::itemClicked, [&mainWindow](QListWidgetItem *item) {
        // 获取所选接口名称
        QString selectedInterface = item->data(Qt::UserRole).toString();
        // 创建并显示分组捕获页面
        CaptureWindow captureWindow(&mainWindow, selectedInterface.toUtf8().constData());
        mainWindow.hide();

        //开始抓包
        handle = pcap_open_live(selectedInterface.toUtf8().constData(), BUFSIZ, 1, 1000, errbuf);
        if(handle==nullptr){
            printf("权限不够！\n");
            exit(1);
        }
        process=false;
        std::thread task(pacp_start);
        captureWindow.exec();
        process=false;
        pcap_close(handle);
        task.detach();
        captured_packets.clear();
        pkthdrs.clear();
        mainWindow.show();
    });
    QObject::connect(&openFileButton, &QPushButton::clicked, [&mainWindow]() {
        //打开文件
        QString filePath = QFileDialog::getOpenFileName(nullptr,"选择文件", "", "所有文件 (*.*)");
        // 创建并显示分组捕获页面
        CaptureWindow captureWindow(&mainWindow, filePath.toUtf8().constData());
        mainWindow.hide();

        //开始抓包
        handle = pcap_open_offline(filePath.toUtf8().constData(),errbuf);
        if(handle==nullptr){
            printf("文件打开失败！\n");
            exit(1);
        }
        process=true;
        std::thread task(pacp_start);
        captureWindow.exec();
        process=false;
        pcap_close(handle);
        task.detach();
        captured_packets.clear();
        pkthdrs.clear();
        mainWindow.show();
    });
    mainWindow.show();
    return app.exec();
}

