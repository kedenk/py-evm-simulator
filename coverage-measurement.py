import sys
import os
import re
from main import main


def get_file_content(file: str) -> str:
    """ Read the content of a file and returns it """

    with open(file, "r") as f:
        return f.read()


def doCoverageMeasurement(inputDir: str):
    if inputDir == None:
        print("No input dir given")
        exit(-1)

    amount_of_inputs = len([name for name in os.listdir(inputDir) if os.path.isfile(os.path.join(inputDir, name))])
    executed = 0

    for inputFileName in os.listdir(inputDir):
        inputFile = os.path.join(inputDir, inputFileName)
        bytecode = get_file_content(inputFile)

        # remove escape character, if they exist
        bytecode = re.sub('[^A-Za-z0-9]+', '', bytecode)

        print("{:2.1f}% of inputs executed".format((executed/amount_of_inputs)*100), end='\r')
        # execute actual py-evm-simulator
        try:
            main(bytecode)
        except Exception as e:
            print(str(e))

        executed += 1

    print("Processing done [{} inputs executed]".format(str(amount_of_inputs)))


if __name__ == '__main__':
    doCoverageMeasurement(sys.argv[1])
