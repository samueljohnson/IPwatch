//gcc -Wall -o "%e" "%f" -l sqlite3

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

void new(char *);
void changed(char *);

int retval;
sqlite3 *db;

FILE *lp;

int sendemail(const char *to, const char *from, const char *subject, const char *message)
{
    int retval = -1;
    FILE *mailpipe = popen("/bin/mail -t", "w");
    if (mailpipe != NULL)
    {
        fprintf(mailpipe, "To: %s\n", to);
        fprintf(mailpipe, "From: %s\n", from);
        fprintf(mailpipe, "Subject: %s\n\n", subject);
        fwrite(message, 1, strlen(message), mailpipe);
        fwrite(".\n", 1, 2, mailpipe);
        pclose(mailpipe);
        retval = 0;
     }
     else
     {
         perror("Failed to invoke sendmail");
     }
     return retval;
}

void parsefile(char* filename) {
	FILE *fp=fopen(filename,"r");
	//if(access(filename, F_OK ) == -1) {
	//	printf("Specified file '%s' do not exist.\n\n",filename);
	//	exit(-1);
	//}
	char lastline[240];
	static char plastline[240]="test";
	while(fgets(lastline, 240, fp));
	
	if(!strcmp(plastline,lastline)){
		//sqlite3_close_v2(db);
		//fprintf(lp,"No change in file detected in parse file. Returning.\n");
		sleep(1);
		fclose(fp);
		return;
	}
	strcpy(plastline,lastline);
	
	if(strstr(lastline,"arpwatch")){
		if(strstr(lastline,"new station")) {
			new(lastline);	//New Station
			fclose(fp);
			return;
		}
		if(strstr(lastline,"flip")) {
			changed(lastline);	//Changed Ethernet Address
			fclose(fp);
			return;
		}
		if(strstr(lastline,"changed ethernet address")){
			changed(lastline);	//Changed Ethernet Address
			fclose(fp);
			return;
		}
		if(strstr(lastline,"reused old ethernet address")) {
			changed(lastline);	//Changed Ethernet Address
			fclose(fp);
			return;
		}
		else {
			fclose(fp);
			return;
		}
	}
	else {
		fclose(fp);
		return;
	}
}

void changed(char* lastline){
//	static char plastline[120]="tmp"; // Previous lastline
	char mac[18],ip[15],macip[35];
	static char lastmacip[35]="tmp";	
	int i=0,j=0,macbegin=0, macend=0,ipbegin=0,ipend=0;

	//if(!strcmp(plastline,lastline)){
		////sqlite3_close_v2(db);
		//int sqlite3_finalize(sqlite3_stmt *stmt);
		//fprintf(lp,"No change in file detected. Returning.\n");
		//sleep(1);
		//return;
	//}
	
	//strcpy(plastline, lastline);
	for(macend=strlen(lastline); lastline[macend]!='('; macend--);
	macend-=2;
	for(macbegin=macend; lastline[macbegin]!=' '; macbegin--);
	macbegin++;
	for(i=macbegin;i<=macend;i++)
		mac[j++]=lastline[i];
	mac[j]='\0';
	strcpy(macip,mac);
	ipend=macbegin-1;
	for(ipbegin=macbegin-2;lastline[ipbegin]!=' ';ipbegin--);
	ipbegin++;
	for(i=ipbegin,j=0;i<ipend;i++)
		ip[j++]=lastline[i];
	ip[j]='\0';
	strcat(macip,ip);
	if(!strcmp(lastmacip,macip)){
		fprintf(lp,"MAC IP pair same as previous one. Ignoring message.\n");
		return;
	}
	strcpy(lastmacip,macip);
	
	int found=0;
	char dbip[15]="0.0.0.0";
	char email[50];
	char useremail[50];
	int sqlite3_initialize();
	sqlite3_stmt *stmt;
	char query[100];
	sprintf(query,"select ip from list where mac='%s'",mac);
	retval = sqlite3_prepare_v2(db,query,-1,&stmt,0);
	retval = sqlite3_step(stmt);
	if(retval==SQLITE_ROW) {
		found=1;
		strcpy(dbip,(const char*)sqlite3_column_text(stmt,0));
		//printf("IP %s found in database for mac %s\n",dbip,mac);
	}
	
	if(strstr(ip,"0.0.0.0")){
		fprintf(lp,"arpwatch bogus message\n");
		return;
	}
	
	if(strstr(ip,"192.168")){
		fprintf(lp,"IP %s ignored\n",ip);
		return;
	}
	if(found){ //IP is not 0.0.0.0
		sprintf(query,"select email from list where mac='%s'",mac);
		retval = sqlite3_prepare_v2(db,query,-1,&stmt,0);
		retval = sqlite3_step(stmt);
		if(retval==SQLITE_ROW) {
			strcpy(email,(const char*)sqlite3_column_text(stmt,0));
			//printf("email for %s is %s\n",dbip,email);
		}


		if(strcmp(dbip,ip)){ //User is using ip not in db.
			char msg[100],sub[100];
			if(strstr(lastline,"flip flop"))
				fprintf(lp,"flip flop: Inform %s (%s) to use ip %s\n",email,mac,dbip);
			else if(strstr(lastline,"reused"))
				fprintf(lp,"reused ip: Inform %s (%s) to use ip %s\n",email,mac,dbip);
			else if(strstr(lastline,"changed"))
				fprintf(lp,"changed ip: Inform %s (%s) to use ip %s\n",email,mac,dbip);
			////sprintf(msg,"Kindly use %s as your IP",dbip);
			////sprintf(sub,"Conflicting IP %s in use",ip);
			
			sprintf(msg,"Tell %s to use %s as their IP",email,dbip);
			sprintf(sub,"Unauthorised IP %s in use by %s",ip,email);
			
			sendemail("someone@example.com","ipwatch-noreply@prl.res.in",sub,msg);
			
			sprintf(query,"select email from list where ip='%s'",ip);
			retval = sqlite3_prepare_v2(db,query,-1,&stmt,0);
			retval = sqlite3_step(stmt);
			if(retval==SQLITE_ROW) {
				strcpy(useremail,(const char*)sqlite3_column_text(stmt,0));
				////sprintf(msg,"%s with mac %s is using your ip.",email,mac);
				////sprintf(sub,"Information");
				
				sprintf(msg,"%s with mac %s is using ip of %s.",email,mac,useremail);
				sprintf(sub,"Information");
				
				sendemail("someone@example.com","ipwatch-noreply@prl.res.in",sub,msg);
			}
		}
		else{
			fprintf(lp,"User is using authorised IP. Ignore message\n");
		}
	}
	else{
		fprintf(lp,"IP %s for mac %s not found in database.\n",ip,mac);
	}
	//sqlite3_close_v2(db);
	int sqlite3_finalize(sqlite3_stmt *stmt);
	//printf("Database file is closed\n");
	return;
}

void new(char* lastline) {
	//static char plastline[120]="tmp"; // Previous lastline
	//if(!strcmp(plastline,lastline)){
		//sleep(1);
		//fprintf(lp,"No change in file detected. Returning.\n");
		//return;
	//}
	//strcpy(plastline, lastline);
	int i=0,j=0,begin,end;
	char mac[18],ip[15],macip[35];
	static char lastmacip[35]="tmp";
	for(begin=strlen(lastline);lastline[begin]!=' ';begin--);
	begin++;
	end=strlen(lastline)-2;
	for(i=begin;i<=end;i++)
		mac[j++]=lastline[i];
	mac[j]='\0';
	strcpy(macip,mac);
	end=begin-2;
	for(begin=end;lastline[begin]!=' ';begin--);
	begin++;
	for(i=begin,j=0;i<=end;i++)
		ip[j++]=lastline[i];
	ip[j]='\0';
	strcat(macip,ip);
	if(!strcmp(lastmacip,macip)){
		fprintf(lp,"MAC IP pair same as previous one. Ignoring message.\n");
		return;
	}
		
	if(strstr(ip,"0.0.0.0")){
		fprintf(lp,"arpwatch bogus message\n");
		return;
	}
	
	if(strstr(ip,"192.168")){
		fprintf(lp,"IP %s ignored\n",ip);
		return;
	}

	strcpy(lastmacip,macip);
	char dbip[15];
	char email[50];
	char useremail[50];
	
	int sqlite3_initialize();
	sqlite3_stmt *stmt;
	char query[100];
	int retval;
	int found=0;
	sprintf(query,"select ip from list where mac='%s'",mac);
	retval = sqlite3_prepare_v2(db,query,-1,&stmt,0);
	retval = sqlite3_step(stmt);
	if(retval==SQLITE_ROW) {
		found=1;
		//*dbip = (const char*)sqlite3_column_text(stmt,0);
		strcpy(dbip,(const char*)sqlite3_column_text(stmt,0));
		//printf("IP %s found in database for mac %s\n",dbip,mac);
	}
	if(found){
		
		sprintf(query,"select email from list where mac='%s'",mac);
		retval = sqlite3_prepare_v2(db,query,-1,&stmt,0);
		retval = sqlite3_step(stmt);
		if(retval==SQLITE_ROW) {
			//*email = (const char*)sqlite3_column_text(stmt,0);
			strcpy(email,(const char*)sqlite3_column_text(stmt,0));
			//printf("email for %s is %s\n",dbip,email);
		}
		
		if(strstr(ip,"0.0.0.0")){
			fprintf(lp,"arpwatch bogus message\n");
			return;
		}
		//printf("Gonna decide whether to send mail or not\n");
		if(strcmp(dbip,ip)){
			char msg[100],sub[100];
			fprintf(lp,"new ip: Inform %s (%s) to use ip %s\n",email,mac,dbip);
			//printf("Previous line is %s\n",plastline);
			////sprintf(msg,"Kindly use %s as your IP",dbip);
			////sprintf(sub,"Conflicting IP %s in use",ip);

			sprintf(msg,"Tell %s to use %s as their IP",email,dbip);
			sprintf(sub,"Unauthorised IP %s in use by %s",ip,email);

			sendemail("someone@example.com","ipwatch-noreply@prl.res.in",sub,msg);
			sprintf(query,"select email from list where ip='%s'",ip);
			retval = sqlite3_prepare_v2(db,query,-1,&stmt,0);
			retval = sqlite3_step(stmt);
			if(retval==SQLITE_ROW) {
				strcpy(useremail,(const char*)sqlite3_column_text(stmt,0));
				////sprintf(msg,"%s with mac %s is using your ip.",email,mac);
				////sprintf(sub,"Information");
				
				sprintf(msg,"%s with mac %s is using ip of %s.",email,mac,useremail);
				sprintf(sub,"Information");
				
				sendemail("someone@example.com","ipwatch-noreply@prl.res.in",sub,msg);
			}
		}
		else{
			fprintf(lp,"User %s is using authorised IP %s. Ignore message\n",email,ip);
		}
	}
	else{
		fprintf(lp,"IP %s for mac %s not found in database.\n",ip,mac);
	}
	//sqlite3_close_v2(db);
	int sqlite3_finalize(sqlite3_stmt *stmt);
	//printf("Database file closed for new entry\n");
	return;
}

int main(int argc, char* argv[]) {

	if(argc!=1){
		printf("Usage: %s \n\n",argv[0]);
		return -1;
	}

	lp=fopen("/var/log/ipwatch.log", "a");
	setbuf(lp, NULL);

//	if(system("pgrep arpwatch > /dev/null")){
//		fprintf(lp,"Starting arpwatch...\n");
//		system("arpwatch -i br0 -N");
//	}

	retval = sqlite3_open_v2("/home/samuel/Programming/arp/database.sl3",&db,SQLITE_OPEN_READONLY,NULL);
	if(retval){
		fprintf(lp,"Unable to open database\n");
		return -1;
	}

	while(1){
		parsefile("/var/log/arpwatch.log");
		int sqlite3_finalize(sqlite3_stmt *stmt);
		//sleep(1);
	}

	fclose(lp);
	return 0;
}
