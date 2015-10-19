/*
* Authors: Harishkumar Katagal(109915793) & Sagar Basavaraj Dhavali(109929325)
* Program to analyze the wireshark trace and outputs the delay for a DNS query.
* We extended the sample program provided by Prof. Aruna to include the functionality.
* Programing Language: C++
* Input: *.pcap file which has wireshark trace
* Output: dnsdelayOut.xml file which contains the delay statistic of DNS queries.
*/

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>

using namespace std;

//Structure to store the information about the packet.
//In this case we have used Linked List to store the packet information.
typedef struct packetList{
	u_char uTransID; //Upper bits of transaction id
	u_char lTransID; //Lower bits of transaction id
	float time; 	 //To store the time in micro sec
	long int sec;	 //To store the time in sec
	packetList* nextPacket; //Pointer too next packet in the list
}packetList;


int main(int argc, char **argv) 
{
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // A pointer to the packet
	packetList* head = NULL; //Head of the Linked List
	ofstream xmlFile;	//Pointer to the output file
	
    //check command line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [pcap file]\n", argv[0]);
        exit(1);
    }
  
    //----------------- 
    //open the pcap file 
    pcap_t *handle; 
	
    char errbuf[PCAP_ERRBUF_SIZE]; // we dont really use this, but is as input to the pcap open function
    
    handle = pcap_open_offline(argv[1], errbuf);   //call pcap library to read the file
 
    if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
      return(2); 
    }
   
   //Open the output file
   xmlFile.open("dnsdelayOut.xml");
   if(xmlFile == NULL)
   {
		cout<<"Error: Cannot open xml file"<<endl;
		return(3);
	}
	xmlFile<<"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"<<endl;
	xmlFile<<"<report>"<<endl;
	xmlFile<<"<description>Web surfing at home with Comcast DNS</description>"<<endl;
		
	
	
	while(packet = pcap_next(handle,&header)){
		//For the request the destination port will be 53.
		//Condition below checks that the destination port is 53 and packet is request.
		if(*(packet+37) == 53 && *(packet+44) == 1){
			//If this is true record the information of packet in the list.
			if(head == NULL){
				packetList* temp = new packetList;
				temp->uTransID = *(packet+42);
				temp->lTransID = *(packet+43);
				temp->time = (header).ts.tv_usec;
				temp->sec = (header).ts.tv_sec;
				temp->nextPacket = NULL;
				head = temp;
			}
			else{
				packetList* temp1 = head;
				while(temp1->nextPacket!=NULL)
					temp1 = temp1->nextPacket;
				packetList* temp = new packetList;
				temp->uTransID = *(packet+42);
				temp->lTransID = *(packet+43);
				temp->time = (header).ts.tv_usec;
				temp->sec = (header).ts.tv_sec;
				temp->nextPacket = NULL;
				temp1->nextPacket = temp;
			}
		}
		//For the response the source port will be 53.
		//Condition below checks that the source port is 53 and packet is response.
		if(*(packet+35) == 53 && *(packet+44) == 129){
			//If this is true check to see if response has a request in the list.
			//If so calculate the time delay and delete the request from the list.
			packetList* temp =head;
			packetList* prevTemp = new packetList;
			while(temp!=NULL){
				//To check if transaction id of response matches with transaction id of request.
				if(temp->uTransID == *(packet+42) && temp->lTransID == *(packet+43)){
					float tempTime =  (header).ts.tv_usec - temp->time;
					int x = (header).ts.tv_sec - temp->sec;
					if(tempTime < 0){
						tempTime = tempTime+1000000;
						if(x>1)
							tempTime = (x-1)*1000000 + tempTime;
					}
					else{
						if(x>=1)
							tempTime = (x)*1000000 + tempTime;
					}
					tempTime = tempTime/1000;
					//Output the delay to the xml file.
					xmlFile<<"<delay>";
					xmlFile<<(int)tempTime;
					xmlFile<<"</delay>"<<endl;
					//printf("\nTime Difference: %d",(int)tempTime);
					if(head->nextPacket == NULL){
						head = NULL;
						break;
					}
					else{
						prevTemp->nextPacket = temp->nextPacket;
						break;
					}
				}
				prevTemp = temp;
				temp = temp->nextPacket;
			}
		}	
	}
	
	/*packetList* temp1 = head;
	while(temp1!=NULL){
		printf("\nTransaction id:%x%x\n",temp1->uTransID,temp1->lTransID);
		cout<<"Time:"<<temp1->time<<endl;
		temp1 = temp1->nextPacket;
	}*/
	xmlFile<<"</report>"<<endl; //Close the xml tag.
	xmlFile.close(); //Close the xml file.
	printf("\n");
    pcap_close(handle);  //close the pcap file 
 
}
