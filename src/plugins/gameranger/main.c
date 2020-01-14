#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../pinc.h"
static cvar_t* gruserid;
static cvar_t* grloginpassword;
static cvar_t* grtimezone;
static cvar_t* grRoomDescription;
static cvar_t* grRoomPassword;
static cvar_t* grallowpublicplayers;
static int serverport;
static int pluginId;
threadid_t* tid;

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;


PCL int OnInit()
{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  char *pcVar5;
  byte bVar6;
  char local_1c [20];
  
  bVar6 = 0;
  /*
  if (_DAT_00041224 != 0) {
    return 0;
  }
  */
  //_DAT_000412cc = 1;
  gruserid = Plugin_Cvar_RegisterInt("gruserid",1,1,2147483647,1,"GameRanger Account ID of the account we want to signin to GameRanger");
  grloginpassword = Plugin_Cvar_RegisterString("grloginpassword","",1, "GameRanger Account Password of the account we want to signin to GameRanger" );
  grtimezone = Plugin_Cvar_RegisterInt("grtimezone",0,-43200,43200,1,"GameRanger Timezone-Delta in seconds shown on profilepage");
  grRoomDescription = Plugin_Cvar_RegisterString ("grRoomDescription","Another GameRanger host",1,"GameRanger-Room description");
  grRoomPassword = Plugin_Cvar_RegisterString("grRoomPassword","",1,"GameRanger-Room password");
  grallowpublicplayers = Plugin_Cvar_RegisterBool("grallowpublicplayers",0,1,"Allow external players to connect");
  //_DAT_00041224 = 1;
  Plugin_Cvar_GetString(grloginpassword,local_1c,16);
  iVar2 = Plugin_Cvar_GetInteger(gruserid);
  uVar4 = 0xffffffff;
  pcVar5 = local_1c;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + (uint)bVar6 * -2 + 1;
  } while (cVar1 != '\0');
  if ((~uVar4 - 1 < 3) || (iVar2 < 2)) {
    Plugin_PrintError("GameRanger: No password or user id has been set!\nPlease add to your server.cfg:\nset grloginpassword password\nset gruserid numericID\nThis has to be before the plugin load command\n" );

	return -1;
  }
  else {
    pluginId = Plugin_GetPluginID();
    iVar2 = Plugin_CreateNewThread( Thread_00014f78,&tid,0);
    if (iVar2 == 0) {
      Plugin_Printf("Failure creating thread for GameRanger plugin\n");
     // uVar3 = 0xffffffff;
	  return -1;
    }
    else {
      Plugin_AddCommand("grkick",FUNC_00014eb1,100);
      Plugin_AddCommand("grconnect",FUNC_000139f4,100);
      Plugin_AddCommand("grsay",FUNC_000136b5,100);
      Plugin_AddCommand("grsayto",FUNC_00012f06,100);
      Plugin_AddCommand("gropenroom",FUNC_0001316e,100);
      Plugin_AddCommand("grcloseroom",FUNC_000133f2,100);
      Plugin_AddCommand("grchangenick",FUNC_000135e6,0x5f);
      Plugin_AddCommand("grchangerealname",FUNC_00013541,100);
      Plugin_AddCommand("gruserinfo",FUNC_00013479,0x28);
      uVar3 = 0;
    }
  }
  //return uVar3;
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

PCL void OnTerminate()

{
  int iVar1;
  int iVar2;
  
  iVar1 = Plugin_Milliseconds();
  _DAT_000412c8 = 1;
  Plugin_Printf("Waiting for GameRanger plugin to terminate\n");
  iVar2 = 0;
  do {
    if (_DAT_000412cc != 0) {
      Plugin_Printf("GameRanger plugin has terminated after %d msec\n",iVar2);
      return;
    }
    Plugin_SleepSec(0);
    iVar2 = Plugin_Milliseconds();
    iVar2 = iVar2 - iVar1;
  } while (iVar2 < 15001 );
  Plugin_Printf("GameRanger plugin couldn\'t terminate within 15000 msec\n");
  return;
}



PCL void OnInfoRequest( pluginInfo_t *info )
{
		  
    info->handlerVersion.major = 3;
    info->handlerVersion.minor = 100;	// Requested handler version

    // =====  OPTIONAL  FIELDS  =====
    info->pluginVersion.major = 12;
    info->pluginVersion.minor = 10;	// Plugin version
    strncpy(info->fullName, "Gameranger",sizeof(info->fullName)); //Full plugin name
    strncpy(info->shortDescription, "This plugin is used to host CoD4 servers inside of the program GameRanger.",sizeof(info->shortDescription)); // Short plugin description
    strncpy(info->longDescription, "This plugin is used to host CoD4 servers inside of the program GameRanger.\nIt can automatically login, open a room and hosting CoD4 inside it\n",sizeof(info->longDescription));		  
		  
}

//WIP

