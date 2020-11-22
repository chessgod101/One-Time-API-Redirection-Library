library Injection;

//One Time API Redirection Library
//Copyright © 2020 Chester Fritz
//GNU Public License.

//This DLL library is designed to redirect a specified API for a one time execution of code upon injection into a process.
//Set RedirAPI to the name of the API you wish to redirect. This is case sensitive.
//Set DLLOFAPI to the name of the DLL you which to redirect including the .dll extension. 
//It should look like this:
//CONST RedirAPI:AnsiString='CreateWindowExA';
//CONST DLLOFAPI:WideString='user32.dll';
//Add your code to execute to the "DoYourStuff" Procedure. I've added a simple PatchMemoryByte function for your convenience.  

uses
Windows;
CONST UnloadDLL:Boolean= FALSE;//if true, this will unload this dll after executing your code. DO NOT USE WITH REGISTER BASED or FASTCALL CALLING CONVENTIONS;
CONST RedirAPI:AnsiString='YOURAPIHERE'; //api to be redirected//////////////////////////////////////////////////////////////////////////////////////////////
CONST DLLOFAPI:WideString='YOURDLLHERE.DLL'; //dll containing that api///////////////////////////////////////////////////////////////////////////////////////
CONST LOCALDLLNAME:WideString='Injection.dll';
var
RedirectedAPIAddr:Cardinal; //Address of the RedirectedAPI
FreeLibAddr:Cardinal; //Address of FreeLibrary
mimgbase:Cardinal;    //Image Base of Main Executable
localModHWND:Cardinal;  // Module Handle of this DLL;
originalBytes:Array[0..4] of byte;  //Original Bytes of Redirected API for Restoration
RedirectedModHWND:Cardinal;//Module Handle of Redirected DLL;


Procedure PatchMemoryByte(VirtualAddress:Integer; val:Byte; IsWriteProtected:Boolean);
var
Tmp:Cardinal;
Begin
if VirtualAddress<0 then exit;

if IsWriteProtected=true then
if VirtualProtect(Pointer(VirtualAddress), 1, PAGE_EXECUTE_READWRITE, Tmp)=false then exit;

PByte(VirtualAddress)^:=val;
End;



//////////////////////////////////////////////////////////////////////////////////////
Procedure DoYourStuff(returnAddress:Integer); STDCALL;//this is where you add your code;
Begin

End;
//////////////////////////////////////////////////////////////////////////////////////



Procedure FixFunction(); STDCALL; //Restores the redirected API bytes
Begin
CopyMemory(Pointer(RedirectedAPIAddr),@originalBytes[0],5);
End;

Procedure InjectionJmpProcedure; assembler;
label
noUnload,DoneUnloadSetup;
ASM
CMP [UnloadDLL],0
JE @noUnload
PUSH localModHWND//Module Handle of Injection.DLL
PUSH RedirectedAPIAddr //address of RedirectedAPI;
PUSH FreeLibAddr//Address of FreeLibrary;
PUSH EAX //VOLATILE REGISTER PRESERVATION SUPPORT FOR REGISTER BASED CALLS OR FASTCALL CONVENTIONS
MOV EAX, DWORD PTR DS:[ESP+$10]//Gets Return Address from Stack
JMP @DoneUnloadSetup
@noUnload:
PUSH RedirectedAPIAddr
PUSH EAX //VOLATILE REGISTER PRESERVATION SUPPORT FOR REGISTER BASED CALLS OR FASTCALL CONVENTIONS
MOV EAX, DWORD PTR DS:[ESP+$8]//Gets Return Address from Stack 
@DoneUnloadSetup:
PUSH EBX //VOLATILE REGISTER PRESERVATION SUPPORT FOR REGISTER BASED CALLS OR FASTCALL CONVENTIONS
PUSH ECX
PUSH EDX
PUSH EAX
CALL DoYourStuff
CALL FixFunction
POP EDX
POP ECX
POP EBX
POP EAX
RET
END;

Function LongJumpCalculator(location,destination:integer;VAR jmp:Cardinal):Boolean;
CONST SelfVal:integer=-5;
Begin
if (location<0) or (destination <0) then
Begin
result:=false;
exit;
End;
jmp:=SelfVal+(destination-location);
result:=true;
End;


Procedure InitilizeAndRedirect();
var
tmp,jmpval:Cardinal;
Begin
mimgbase:=GetModuleHandleW(nil);
RedirectedModHWND:=GetModuleHandleW(@DLLOFAPI[1]);
if RedirectedModHWND=0 then exit;

localModHWND:=GetModuleHandleW(@LOCALDLLNAME[1]);
if localModHWND=0 then Exit;


tmp:=GetModuleHandleW(WideString('kernel32.dll'));
if tmp=0 then Exit;


FreeLibAddr:=Cardinal(GetProcAddress(tmp,AnsiString('FreeLibrary')));
if FreeLibAddr=0 then Exit;


RedirectedAPIAddr:=Cardinal(GetProcAddress(RedirectedModHWND,PAnsiChar(@RedirAPI[1])));
if RedirectedAPIAddr= 0 then begin

exit;
end;
VirtualProtect(Pointer(RedirectedAPIAddr),10,PAGE_EXECUTE_READWRITE ,tmp);
CopyMemory(@originalBytes[0],Pointer(RedirectedAPIAddr),5);
LongJumpCalculator(Integer(RedirectedAPIAddr),Integer(@InjectionJmpProcedure),jmpval);
PByte(RedirectedAPIAddr)^:=$e9;  //set jmp
pCardinal(RedirectedAPIAddr+1)^:=jmpval;  //set jmp location
End;

begin //Function Main

InitilizeAndRedirect;

end.
