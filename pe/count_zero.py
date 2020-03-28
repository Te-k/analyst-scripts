import argparse
import lief


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('PE', help='an integer for the accumulator')
    args = parser.parse_args()

    binary = lief.parse(args.PE)

    i = 0
    for s in binary.sections:
        c = s.content.count(0)
        print("{} - {} - {} zeros (total {} - {:.2f}%)".format(
            i,
            s.name,
            c,
            s.size,
            (c/s.size)*100
            )
        )
        i += 1
