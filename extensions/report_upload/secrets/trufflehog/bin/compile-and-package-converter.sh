
export LIBRARY_PATH=./lib
export CLASSES_PATH=./src/main/java
export RESOURCES_PATH=./src/main/resources
export OUTPUT_PATH=classes

# compile model, loader and converter
javac -d $OUTPUT_PATH -cp $LIBRARY_PATH/*:$CLASSES_PATH:$RESOURCES_PATH $CLASSES_PATH/ext/trufflehog/model/*.java $CLASSES_PATH/ext/trufflehog/*.java

# package jar with java classes and resources
jar cvf trufflehog-converter.jar -C $OUTPUT_PATH . -C $RESOURCES_PATH .
