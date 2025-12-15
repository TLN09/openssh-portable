from math import sqrt

def parse_results(data: str) -> list[float]:
    lines = (line for line in data.splitlines() if not line.isdigit())
    start = 0.0
    end = 0.0
    result = []
    for line in lines:
        if line.startswith('auth start'):
            start = float(line.split(':')[-1].strip())
        elif line.startswith('auth end'):
            end = float(line.split(':')[-1].strip())
            result.append(
                end - start
            )
    
    return result

def calculate_stats(data: list[float]) -> None:
    data.sort()
    minimum = data[0]
    maximum = data[1]
    median = data[len(data) // 2]
    mean = sum(data) / len(data)
    variance = sum(pow(d - mean, 2) for d in data) / len(data)
    std_deviation = sqrt(variance)
    print('min,max,median,mean,variance,std. dev.')
    print(f'{minimum},{maximum},{median},{mean},{variance},{std_deviation}')


def main(results: str):
    with open(results, 'r', encoding='utf-8') as f:
        data = f.read()

    data = parse_results(data)
    calculate_stats(data)

if __name__ == '__main__':
    from argparse import ArgumentParser
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--results', help='File containing results from test', type=str)
    args = arg_parser.parse_args()
    
    main(args.results)