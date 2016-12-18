#
# Makefile for SMTP client
#
# Bob Eager   December 2004
#
# Product name
#
PRODUCT		= smtp
#
# Target directory
#
TARGET		= f:\binp
#
# Compiler setup
#
CC		= icc
DEFS		= -DTCPV40HDRS
!IFDEF DEBUG
DBUG		= -DDEBUG
!ELSE
DBUG		=
!ENDIF
!IFDEF	PROD
CFLAGS		= $(DEFS) $(DBUG) -G4 -Gm -Gn -O -Q -Se -Tl30
CLIB		= cppom30o.lib
!ELSE
CFLAGS		= $(DEFS) $(DBUG) -G4 -Gm -Gn -Q -Se -Ti -Tl30 -Tm -Tx
CLIB		= cppom30.lib
!ENDIF
#
# Names of library files
#
NETLIB		= ..\netlib\netlib.lib
LIBS		= so32dll.lib tcp32dll.lib $(CLIB) \
		  $(NETLIB) os2386.lib
#
# Names of object files
#
OBJ		= smtp.obj client.obj netio.obj log.obj
#
# Other files
#
DEF		= $(PRODUCT).def
LNK		= $(PRODUCT).lnk
README		= readme.txt
#
# Final executable file
#
EXE		= $(PRODUCT).exe
#
# Distribution
#
DIST		= dist.zip
NETLIBDLL	= ..\netlib\netlib.dll
#
# Archive
#
ARCH		= arch.zip
#
#-----------------------------------------------------------------------------
#
$(EXE):		$(OBJ) $(LNK) $(DEF)
!IFDEF	PROD
		ilink /nodefaultlibrarysearch /nologo /exepack:2 @$(LNK)
		lxlite $(EXE)
		eautil $(EXE) nul /s
!ELSE
		ilink /nodefaultlibrarysearch /debug /nobrowse /nologo @$(LNK)
!ENDIF
#
# Object files
#
smtp.obj:	smtp.c smtp.h log.h
#
client.obj:	client.c smtp.h netio.h auth.h log.h
#
netio.obj:	netio.c netio.h
#
log.obj:	log.c log.h
#
# Linker response file. Rebuild if makefile changes
#
$(LNK):		makefile
		@if exist $(LNK) erase $(LNK)
		@echo /map:$(PRODUCT) >> $(LNK)
		@echo /out:$(PRODUCT) >> $(LNK)
		@echo $(OBJ) >> $(LNK)
		@echo $(LIBS) >> $(LNK)
		@echo $(DEF) >> $(LNK)
#
clean:		
		-erase $(OBJ) $(LNK) $(PRODUCT).map csetc.pch
#
install:	$(EXE)
		@copy $(EXE) $(TARGET) > nul
#
dist:		$(EXE) $(NETLIBDLL) $(README)
		zip -9 -j $(DIST) $**
#
arch:		$(EXE) $(README) $(DEF) *.c *.h makefile
		zip -9 -j $(ARCH) $**
#
# End of makefile for SMTP client
#
