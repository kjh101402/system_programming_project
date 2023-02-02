import sys
import string
import re
import struct
import math
from two_pass import two_pass

instructions = {}           # 주소-명령어 쌍 저장
text_symbol_table = {}           # 심볼-주소 쌍 저장
data_symbol_table = {}      # data 섹션 심볼
rodat = {}                  # read only data
rwdat = {}                  # .data 영역 변수
literal_pool_data = []      # (label, data) 쌍으로 저장할 리스트
section = 'text'            # 기본값  text

global_label = []           # global label 저장 리스트
original = []               # 원래 코드 저장 리스트

splitter = re.compile(r'([ \t\n,\[\]\{\}])')                    # 나눌 단위(공백, 탭, 뉴라인, 콤마)
pc = 0x8080
literal_pool_start_addr = 0

def directive_process(tokens, line):
    global pc
    global section
    global literal_pool_start_addr
    print('\tDIRECTIVE ' + tokens[0] + ' FOUND')            # 찾은 섹션을 출력
    dir_type = tokens[0][1:]                                # Directive . 떼고 저장
    tokens = tokens[1:]                                     # 다음 토큰들
    if dir_type == 'asciz' or dir_type == 'ascii':      #아스키 문자열
        st = re.findall('(\".+\")', line)[0]            # 큰 따옴표 안 문장 찾음
        store_str = st                                  # 저장할 문자열
        store_str = store_str.lstrip('"').rstrip('"')   # 큰따옴표 떼기
        if dir_type == 'asciz':                         # asciz면 널문자 추가
            store_str += '\0'

        while len(store_str) > 0:                       # 4바이트씩 나눠서 저장
            if section == 'text':
                rodat[pc] = store_str[:4]
            elif section == 'data':
                rwdat[pc] = store_str[:4]
            store_str = store_str[4:]
            pc += 4

        st_tokens = splitter.split(st)                  
        st_tokens = [tok for tok in st_tokens if re.match('\s*$', tok) == None]
        tokens = tokens[len(st_tokens):]                # 문자열 토큰에서 제거

    elif re.match('(word|hword|byte)' ,dir_type):
        if section == 'text':
            rodat[pc] = tokens[0]
        elif section == 'data':
            rwdat[pc] = tokens[0]
        tokens = tokens[1:]
        pc += 4
    
    elif re.match('(text|data)', dir_type):
        section = dir_type
        if section == 'data':
            literal_pool_start_addr = pc
            pc += (4 * len(literal_pool_data))
        pass
    
    elif re.match('global', dir_type):
        global_label.append(tokens[0])
        tokens = tokens[1:]
    
    elif re.match('end', dir_type):
        section = dir_type
        
    else:
        pass
    return tokens
    
    
def label_process(tokens):
    print('\tLABEL ' + tokens[0].rstrip(':') + ' FOUND')    # 찾은 라벨 뒤에 : 떼고 출력
    label = tokens[0].rstrip(':')
    if label in text_symbol_table or label in data_symbol_table:    # 중복시 에러 출력
        print('ERROR: Lablel %s is already exist'%label)
        sys.exit(1)
    if section == 'text':                                   # 섹션 나눠서 저장
        text_symbol_table[label] = pc
    elif section == 'data':
        data_symbol_table[label] = pc
    tokens = tokens[1:]                                     # 토큰 리스트 맨 앞에 것 제거
    return tokens


# 첫번째로 1나오는 비트 위치 찾는 함수
def getFirstSetBitPos(n):
    return int(math.log2(n & -n)+1)

def check_immediate(imme):      #mov로 만들 수 있는지 확인하는 함수
    if imme < 0:
        imme = ~imme
        imme &= 0xffffffff
    
    if imme & (~0xff) == 0:
        return True
    
    else:
        first_one_bit = getFirstSetBitPos(imme)
        first_one_bit &= ~1
        if imme & (~0xff << first_one_bit) == 0:
            return True
        
        elif imme & ~0xc000003f == 0:
            return True
        
        elif imme & ~0xf000000f == 0:
            return True
        
        elif imme & ~0xfc000003 == 0:
            return True
        
        else:
            return False
            
def string_to_num(num):
    if(re.match('^#-?[0-9]+$', num)):                     # 10진수
        return int(num[1:])
    elif(re.match('^#(-?0x[0-9a-f]+)$', num)):            # 16진수
        return int(num[1:], 16)
    elif(re.match('^#(-?0[0-8]+)$', num)):                # 8진수
        return int(num[1:], 8)
    elif(re.match('^#(-?0b[0-1]+)$', num)):               # 2진수
        return int(num[1:], 2)
    else:                                               # 이외는 오류
        print('ERROR: Invalid number format')
        sys.exit(1)

def ldr_process(tokens):                                    # mov로 바꾸거나 label 새거 박아서 반환
    if re.match('^=-?(0x|0b|0)?\\d+$', tokens[3]):           # =숫자 처리
        imme = string_to_num('#' + tokens[3].lstrip('='))
        if check_immediate(imme):                           # True면 mov로 변환
            tokens[0] = 'mov'
            tokens[3] = '#' + tokens[3].lstrip('=')         # mov니까 =도 #으로 변경
            return tokens
        
        # False면 literal pool에 저장해야함.
        temp_label = 'constant_' + tokens[3].lstrip('=')       # 임시 라벨 부여
        literal_pool_data.append((temp_label, imme))        # (라벨, 값) 쌍으로 저장, 나중에 literal pool, symbol_table에 저장
        tokens[3] = temp_label                              # 임시 라벨로 변환
        return tokens
        
    elif re.match('^=.+$', tokens[3]):                      # =label 처리
        temp_label = tokens[3].lstrip('=') + 'addr'         # 라벨 주소라고 라벨 만듦
        literal_pool_data.append((temp_label, tokens[3].lstrip('='))) # 라벨, 라벨 쌍으로 저장
        tokens[3] = temp_label
        return tokens

    return tokens                                           # 둘 다 아니면 그냥 반환
    


def literal_pool_process(start):
    for labels in literal_pool_data:                        # literal pool 저장할 것 저장
        symbol = labels[0]
        value = labels[1]
        if re.match('^constant_-?(0x|0b|0)?\\d+$', symbol): # 상수 저장 시
            text_symbol_table[symbol] = start
            rodat[start] = value
            start += 4

        elif re.match('.+addr', symbol):                    # 라벨 주소 저장 시
            if value in text_symbol_table:
                addr = text_symbol_table[value]
            elif value in data_symbol_table:
                addr = data_symbol_table[value]
            else:
                print('ERROR: %s symbol doesnt exist'%value)
                sys.exit(1)
            
            text_symbol_table[symbol] = start
            rodat[start] = addr
            start += 4
    literal_pool_data.clear()

#lines = sys.stdin.readlines()                           # read lines (표준 입력)

def main(lines):
    global pc
    global literal_pool_start_addr
    for line in lines:                                      # 파일의 모든 줄이 끝날 때까지
        tokens = splitter.split(line)                       # 줄을 토큰으로 나눔
        
        original.append(line)
        
        #print(tokens)                                       # 토큰 리스트 출력
        tokens = [tok for tok in tokens
                if re.match('\s*$', tok) == None]         # 토큰 중에서 공백, 탭, 뉴라인 등 빈 것들 제거
        #print(tokens)                                       # 토큰 리스트 출력
        # print('%x: %s'%(pc, line))
        # 주석 처리
        comment = 0
        for x in tokens:
            if x.startswith('@'):
                break
            comment += 1
        tokens = tokens[:comment]

        while len(tokens) > 0:                                          #토큰 리스트 길이 0보다 큰 동안(명령어 있는 동안) 반복
            if tokens[0].endswith(':'): # process label                 라벨 처리 ( : 으로 끝나면)
                tokens = label_process(tokens)
                
                continue
            elif tokens[0].startswith('.'): # process directive         섹션 나누기
                # print('\tDIRECTIVE ' + tokens[0] + ' FOUND')            # 찾은 섹션을 출력
                # tokens = tokens[1:]
                tokens = directive_process(tokens, line)
                if section == 'end':
                    break
                continue
            
            elif tokens[0] == 'ldr':
                tokens = ldr_process(tokens)
                instructions[pc] = tokens
                pc += 4
                break
                
            else: # process instruction COVER                           그 외에는 명령어 처리
                instructions[pc] = tokens
                pc += 4
                break
        if section == 'end':
            break
    
    if literal_pool_start_addr == 0:
        literal_pool_start_addr = pc
    literal_pool_process(literal_pool_start_addr)                    
            
    machine = two_pass(instructions, text_symbol_table, data_symbol_table)


    print('\n\toriginal code')
    for idx, x in enumerate(original):
        print("%3d : "%idx, x.rstrip('\n'))

    # print(instructions)
    print('\n\n%-4s : %-40s    \t%s'%('addr', 'instructions', 'machine code'))
    print('-'*100)
    for x in instructions.keys():
        # print("%x : "%x, instructions[x], '\t->\t', hex(machine[x]))
        print("%x : %-40s  =>\t%s"%(x, ' '.join(instructions[x]), hex(machine[x])))
        
    print('\n\tread only data')
    for x in rodat.keys():
        print("%x : "%x, rodat[x])
        
    print('\n\tread write data')
    for x in rwdat.keys():
        print("%x : "%x, rwdat[x])
        
    print('\n\ttext_symbol table')
    for x in text_symbol_table.keys():
        print("%-10s : %x"%(x, text_symbol_table[x]))
        
    print('\n\tdata_symbol table')
    for x in data_symbol_table.keys():
        print("%-10s : %x"%(x, data_symbol_table[x]))