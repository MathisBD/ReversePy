
ifndef PIN_ROOT 
	PIN_ROOT=/home/mathis/src/StageL3/pin-3.19-98425-gd666b2bee-gcc-linux
endif
OUTPUT_DIR=output
TOOL=obj-intel64/tool.so

PROG?=ls

# example usage : make -s PROG="python prog.py"
all:
# build
	mkdir -p obj-intel64 
	make --file makefile.pin PIN_ROOT=$(PIN_ROOT) obj-intel64/tool.so
# run
	mkdir -p $(OUTPUT_DIR)
	$(PIN_ROOT)/pin -t $(TOOL) -o $(OUTPUT_DIR) -- $(PROG)

clean:
	rm -f -r obj-intel64
	rm -f pin.log pintool.log
	rm -f tototo tototo_after
	rm -f tmp*
	rm -f -r __pycache__
