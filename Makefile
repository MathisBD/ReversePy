
ifndef PIN_ROOT
	PIN_ROOT=$(CURDIR)/../pin-3.19-98425-gd666b2bee-gcc-linux
endif
OUTPUT_DIR=$(CURDIR)/output
TOOL=obj-intel64/tool.so

PROG?=ls

# example usage : make PROG="python3 prog.py"
all:
# build
	mkdir -p obj-intel64 
	make --file makefile.pin PIN_ROOT=$(PIN_ROOT) obj-intel64/tool.so
# run
	mkdir -p $(OUTPUT_DIR)
	$(PIN_ROOT)/pin -t $(TOOL) -o $(OUTPUT_DIR) -- $(PROG)

clean:
	rm -f -r ./obj-intel64
	rm -f -r $(OUTPUT_DIR)
	rm -f ./pin.log ./pintool.log
