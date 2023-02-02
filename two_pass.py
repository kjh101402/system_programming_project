import sys
import string
import re
import struct
import math

# 변환에 사용할 심볼 테이블
text_symbol_table = {}
data_symbol_table = {}

# condiiton 4bit 매핑
cond = {'eq': 0, 'ne': 1, 'hs': 2, 'cs': 2, 'lo': 3,
        'cc': 3, 'mi': 4, 'pl': 5, 'vs': 6, 'vc': 7,
        'hi': 8, 'ls': 9, 'ge': 10, 'lt': 11, 'gt': 12,
        'le': 13, 'al': 14, 'nv': 15}

# 레지스터 매핑
registers = {'r0': 0, 'r1': 1, 'r2': 2, 'r3': 3, 'r4': 4,
             'r5': 5, 'r6': 6, 'r7': 7, 'r8': 8, 'r9': 9,
             'r10': 10, 'r11': 11, 'r12': 12, 'r13': 13,
             'r14': 14, 'r15': 15, 'sl': 10, 'fp': 11,
             'ip': 12, 'sp': 13, 'lr': 14, 'pc': 15}

# data_processing 명령어 모음
data_processing = {'and':0, 'eor':1, 'sub':2, 'rsb':3, 
                   'add':4, 'adc':5, 'sbc':6, 'rsc':7,
                   'tst':8, 'teq':9, 'cmp': 10, 'cmn':11,
                   'orr':12, 'mov': 13, 'bic':14, 'mvn':15}


# data_block 모드 모음
modes = ['fd', 'fa', 'ed', 'ea', 'ia', 'ib', 'da', 'db']

# 첫번째로 1나오는 비트 위치 찾는 함수
def getFirstSetBitPos(n):
    return int(math.log2(n & -n)+1)

# 정규식 생성 함수
def make_regexp(li):
    res = '('                               # 그룹으로 만들기 위해 ( 시작
    for elem in li:
        res += elem + '|'                   # 키들 하나씩 or하면서 추가
    res = res.rstrip('|')                   # 다 추가하면 or 하나 지움
    res += ')'                              # 소괄호 닫음
    #print('res = ', res)
    return res                              # 만들어진 정규식 반환

cond_regexp = make_regexp(cond.keys())      # cond 딕셔너리의 키들로 정규식 생성
dp_regexp = make_regexp(data_processing.keys()) # data_processing 명령어 정규식 생성
mode_regexp = make_regexp(modes)

dp_format = dp_regexp + cond_regexp + '?' + 's' + '?'         # data_processing 명령어 정규식
swi_format = 'swi' + cond_regexp + '?'                          # swi 명령어 정규식
mul_format = '(mul|mla)' + cond_regexp + '?s?'                  # mul 명령어 정규식
mul_long_format = '(u|s)(mul|mla)l' + cond_regexp + '?s?'       # mull 정규식
ldr_format = 'ldr' + cond_regexp + '?b?'                        # ldr 명령어 정규식
str_format = 'str' + cond_regexp + '?b?'                        # str
adr_format = 'adr' + cond_regexp + '?'                          # adr
branch_format = 'b(l)?' + cond_regexp + '?'                     # branch
bx_format = 'bx' + cond_regexp + '?'                            # branch exchange
block_data_format = '(ldm|stm)' + cond_regexp + '?' + mode_regexp + '?' # ldm, stm

# condition 처리 함수
def process_cond_field(mach_code, tok):
    cond_field = tok[:2]                            # 토큰의 2번째 글자까지 (lt면 lt만) s를 배제하기 위함
    if cond_field in cond:                          # cond 안에 condtion field가 있으면
        mach_code |= cond[cond_field] << 28         # 그 값을 LS 28한 값을 or 처리한다.
        tok = tok[2:]                               # cond 이후 값 남김
#        print('\tCOND is set to ' + str(cond[cond_field]))
        print('\tCOND is set to ' + str(bin(cond[cond_field])))         # condtion code 이진수로 출력
    else: # if cond is undefined                                        condition이 없는 경우
        mach_code |= 14 << 28                                           # AL을 코드에 추가
        print('\tCOND is undefined')                                    # condition 없다고 출력
    return (mach_code, tok)                                             # 중간 머신 코드와 남은 명령어 토큰 반환

# CPSR을 설정하게 만드는 S를 처리하는 함수
def process_S_flag(mach_code, tok):
    if len(tok) > 0 and tok[0] == 's':                                      # 앞에서 다 처리해서 s만 남았을 것
        print('\tS flag is set')                        # 있으면 있다고 출력
        mach_code |= 1 << 20                            # S는 20번째 비트임
        tok = tok[1:]                                   # 명령어 토큰 s 버림
    return (mach_code, tok)                             # 중간 머신 코드와 남은 명령어 토큰 반환


# #숫자 포맷을 숫자로 변환하여 반환
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


# imme 값을 처리하는 함수
def process_immediate(mach_code ,num, instruction):                             # 숫자 포맷에 따라 반환하는 함수
    
    imme = string_to_num(num)
        
    if imme < 0:                                        # 음수면 bit not 해준뒤
        imme = ~imme
        imme &= 0xffffffff                                  # 32bit에 맞춰서 절삭
        mach_code = inverse_instruction(mach_code, instruction)  # 음수니까 대응되는 명령어로 교체
            
    if(imme & (~0xff) == 0):                            # 0~255 는 바로 기계어 입력
        mach_code |= imme
            
    else:
        first_one_bit = getFirstSetBitPos(imme)         # 첫 1나오는 위치 찾음
        first_one_bit &= ~1                             # 짝수 시프트만 되니까 홀수면 1 빼기
        if(imme & ~(0xff << first_one_bit) == 0):       # 뭉탱이로 같이 있으면 짝수번 시프트해서 뭉쳐있는지 확인
            rot = int((32 - first_one_bit) / 2)         # 오른쪽 rotate니까 32에서 첫 1까지 빼고 2로 나눈다
            mach_code |= rot << 8                       # 시프트는 8bit부터 시작
            mach_code |= imme >> first_one_bit          # imme는 당겨서 하위 8bit에 채움
                
        elif((imme & ~0xc000003f) == 0):                # ror # 2 경우
            rot = 1                                     # #rot = 1
            tmp = (imme & 0xc0000000) >> 30             # rot해서 넘어간 상위 2비트 가져옴
            imme = (imme << 2) & 0xffffffff             # 좌시프트로 공간 만들고 32bit 넘어간 비트 자름
            imme |= tmp                                 # 합침
            mach_code |= rot << 8                       # 기계어에 #rot 추가
            mach_code |= imme                           # 기계어에 imme 추가

        elif((imme & ~0xf000000f) == 0):                # ror #4 경우
            rot = 2
            tmp = (imme & 0xf0000000) >> 28             # 상위 4비트
            imme = (imme << 4) & 0xffffffff
            imme |= tmp
            mach_code |= rot << 8
            mach_code |= imme

        elif((imme & ~0xfc000003) == 0):                # ror #6 경우
            rot = 3
            tmp = (imme & 0xfc000000) >> 26             # 상위 6비트
            imme = (imme << 6) & 0xffffffff
            imme |= tmp
            mach_code |= rot << 8
            mach_code |= imme
                
        else:                                           # 짝수 shift 로 표현 못하면 에러 출력
            print('ERROR: Invalid number')
            sys.exit(1)
    
    return mach_code
    


# imme 값이 음수인 경우 명령어를 뒤바꾸고 imme에 bit not 한 값이 들어감
def inverse_instruction(mach_code, instruction):
    if instruction == 'mov' or instruction == 'mvn':            # mov, mvn끼리 반대
        mach_code ^= (0b10 << 21)                               # xor 취함
    elif instruction == 'cmp' or instruction == 'cmn':          # cmp, cmn끼리 반대
        mach_code ^= (0b1 << 21)
    elif instruction == 'sub' or instruction == 'add':          # sub, add 반대
        mach_code ^= (0b110 << 21)
    elif instruction == 'and' or instruction == 'bic':          # and, bic 반대
        mach_code ^= (0b1110 << 21)
    elif instruction == 'adc' or instruction == 'sbc':          # adc, sbc 반대
        mach_code ^= (0b0011 << 21)
    else:                                                       # 나머지는 오류 출력
        print('ERROR: Invalid operand')
        sys.exit(1)
        
    return mach_code


# shift 처리 함수
def process_shift(mach_code, args):
    print('shift args:', args)
    if(len(args) == 0):                                             # 시프트 없으면 그냥 통과
        return mach_code, args
    
    if(mach_code & (1 << 25) != 0 and len(args) != 0):              # 시프트는 imme에 사용 불가
        print('ERROR: Invalid syntax (shift only with register)')
        sys.exit(1)
    
    if(args[0] != ','):                                             # 콤마 확인
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if(args[1] == 'lsl'):                                           # LSL 범위는 1 ~ 31
        up = 31
        
    elif(args[1] == 'lsr'):                                         # lsr 1 ~ 32
        up = 32
        mach_code |= (0b01 << 5)                                    # sh 필드 설정
        
    elif(args[1] == 'asr'):                                         # asr 1 ~ 32
        up = 32
        mach_code |= (0b10 << 5)                                    # sh 설정

    elif(args[1] == 'ror'):                                         # ror 1 ~ 31
        up = 31
        mach_code |= (0b11 << 5)                                    # sh 설정

    elif(args[1] == 'rrx'):                                         # rrx는 뒤가 없음
        mach_code |= (0b11 << 5)                                    # ror #0 로 설정
        args = args[2:]

        return mach_code, args                                            # 바로 반환
    
    if(args[2] in registers):                                       # Rs가 pc이면 에러 출력
        if(args[2] == 'r15' or args[2] == 'pc'):
            print('ERROR: Invalid syntax')
            sys.exit(1)
        mach_code |= (registers[args[2]] << 8)                      # 아니면 Rs 설정하고 포맷 맞춤
        mach_code |= (1 << 4)
        
    elif(args[2][0] == '#'):                                        # imme값이면
        num_of_shift = string_to_num(args[2])
        print('#shift: ', num_of_shift)
        if(num_of_shift == 0):                                      # 0이면 LSL #0으로 바꿈
            mach_code &= (~(0b11 << 5))
        
        elif(num_of_shift >= 1 and num_of_shift <= up):             # 범위 안이면
            mach_code |= ((num_of_shift & 0b11111) << 7)            # #shift 설정
        
        else:                                                       # 그 외는 에러 출력
            print('ERROR: Invalid syntax')
            sys.exit(1)
        
    args = args[3:]
    return mach_code, args

# Data Processing 명령어 피연산자 2개 처리하는 함수
def process_2_args(mach_code, args, instruction):
    # match_reg is list of matching register
    if args[0] in registers:                                # 첫번째 피연산자가 레지스터면
        mach_code |= registers[args[0]] << 12               # Rd부분에 맞게 시프트 후 추가
    else: # destination must be register                    레지스터 아니면 오류 출력
        print('ERROR: Invalid operand')
        sys.exit(1)                                         # 프로그램 종료

    if args[1] != ',':                                      # 중간에 콤마 없으면
        print('ERROR: Invalid syntax')                      # 에러 출력 후 종료
        sys.exit(1)

    if args[2] in registers:                                # 두번째 피연산자가 레지스터면
        mach_code |= registers[args[2]]                     # 레지스터 값 기계어에 추가
    elif args[2][0] == '#':                                 # #이면 immediate값인데 패스 됨
        mach_code |= 1 << 25                                # I를 1로 설정
        mach_code = process_immediate(mach_code, args[2], instruction)     # imme값 처리
                
    else: # operand is neither register nor constant        이외에는 에러 출력 후 종료
        print('ERROR: Invalid operand')
        sys.exit(1)
        
    args = args[3:]
    
    mach_code, args = process_shift(mach_code, args)              # shift 처리

    return mach_code

# Data Processing 명령어 인자 3개 처리
def process_3_args(mach_code, args, instruction):
    if args[0] in registers:        # 첫번째 피연산자
        mach_code |= registers[args[0]] << 12
    else:                                           # 레지스터 아니면 오류 출력
        print('ERROR: Invalid operand')
        sys.exit(1)
        
    if args[1] != ',':
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if(len(args) == 3 or len(args) == 6):       # rd, rn이 같으면 생략가능
        mach_code |= registers[args[0]] << 16   # 두번째 피연산자
        rm = args[2]                            # 세번째 피연산자
        args = args[3:]
        
    elif(len(args) == 5 or len(args) == 8):
        if args[2] in registers:                # 두번째 피연산자
            mach_code |= registers[args[2]] << 16
        else:
            print('ERROR: Invalid operand')
            sys.exit(1)
        if(args[3] != ','):
            print('ERROR: Invalid syntax')
            sys.exit(1)
        rm = args[4]                            # 세번째 피연산자
        args = args[5:]
    else:                                       # 피연산자 개수 안맞으면 에러 출력
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if rm in registers:                         # 레지스터면 그냥 추가
        mach_code |= registers[rm]
    elif rm[0] == '#':                          # imme 값이면
        mach_code |= 1 << 25                                # I를 1로 설정
        mach_code = process_immediate(mach_code, rm, instruction)     # imme값 처리
        
    else: # operand is neither register nor constant        이외에는 에러 출력 후 종료
        print('ERROR: Invalid operand')
        sys.exit(1)
    
    (mach_code, args) = process_shift(mach_code, args)      # shift 처리
    
    return mach_code



# Data_processing 명령어 처리 함수
def data_processing_instruction(mach_code, tok, args):

    inst_set = re.findall(dp_format, tok)

    instruction = inst_set[0][0]
    mach_code = data_processing[instruction] << 21                      # 21~24 opcode 추가
    tok = tok[3:]
    
    # 순서가 S가 먼저 처리되고 그 다음 cond를 처리함 (최근)
    # 우리 버전은 cond 먼저 처리 후 s 처리
    (mach_code, tok) = process_cond_field(mach_code, tok)       # condition 처리
    (mach_code, tok) = process_S_flag(mach_code, tok)           # s flag 처리
    
    if(len(tok) != 0):
        print('ERROR: Invalid instruction syntax')
        sys.exit(1)
    
    if(re.match('(tst|teq|cmp|cmn|mov|mvn)', instruction)):
        if(re.match('(tst|teq|cmp|cmn)', instruction)):
            mach_code |= 1 << 20                                                # S 1로 설정
        mach_code = process_2_args(mach_code, args, instruction)                 # 피연산자 처리
    else:
        mach_code = process_3_args(mach_code, args, instruction)                # 피연산자 처리
    return mach_code, tok


# SWI 명령어 처리 함수
def swi_instruction(mach_code, tok, args):
    if(len(args) == 0):                     # 뒤에 아무것도 없으면 에러 출력력
        print('ERROR: Invalid syntax')
        sys.exit(1)
    mach_code |= (0b1111 << 24)             # 포맷 맞춰서 비트 추가
    tok = tok[3:]
    
    (mach_code, tok) = process_cond_field(mach_code, tok)   # cond 처리

    imme = string_to_num('#' + args[0])             # imme값 확인

    
    args = args[1:]
    if(imme < 0):                                   # 음수면 오류 출력
        print('ERROR: swi need 0 ~ 2^24 - 1 number')
        sys.exit(1)
    
    if(imme & (~(0xffffff)) != 0):                  # 범위 벗어나면 에러 출력
        print('ERROR: swi need 0 ~ 2^24 - 1 number')
        sys.exit(1)
    
    mach_code |= imme                               # 범위 내면 비트 처리
    
    if(len(args) != 0):                             # 뒤에 뭐 더 있으면 에러 출력
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    return mach_code


# mul, mla 처리 함수
# MUL{cond}{S} {Rd}, Rm, Rs
# MLA{cond}{S} Rd, Rm, Rs, Rn         
def mul_instruction(mach_code, tok, args):
    mach_code |= (0b1001 << 4)
    
    inst = tok[:3]
    tok = tok[3:]
    
    (mach_code, tok) = process_cond_field(mach_code, tok)
    (mach_code, tok) = process_S_flag(mach_code, tok)
    
    if(inst == 'mul'):
        if(len(args) == 3):                 # Rd 생략시 Rn이 Rd와 Rm이 되고 Rm이 Rn이 된다
            if args[0] in registers:        # RD
                if  args[0] == 'pc' and args[0] == 'r15':       # pc는 못씀
                    print('ERROR: Invalid syntax (MUL cannot use r15(pc))')
                    sys.exit(1)
                
                mach_code |= (registers[args[0]] << 16)         # RD 자리
                mach_code |= (registers[args[0]] << 8)          # RS 자리
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)

            if args[1] != ',':
                print('ERROR: Invalid syntax')
                sys.exit(1)
                
            if args[2] in registers:
                if registers[args[2]] == 15:
                    print('ERROR: Invalid syntax (MUL cannot use r15(pc)')
                    sys.exit(1)
                    
                mach_code |= registers[args[2]]                 # Rm 자리
            
                
        elif(len(args) == 5):
            if args[0] in registers:
                if registers[args[0]] == 15:
                    print('ERROR: Invalid syntax (MUL cannot use r15(pc)')
                    sys.exit(1)

                mach_code |= (registers[args[0]] << 16)         # Rd
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
            
            if args[1] != ',':
                print('ERROR: Invalid syntax')
                sys.exit(1)
                
            if args[2] in registers:
                if registers[args[2]] == 15:                    # pc 금지
                    print('ERROR: Invalid syntax (MUL cannot use r15(pc)')
                    sys.exit(1)
                    
                if registers[args[0]] == registers[args[2]]:        # Rd와 Rm이 같으면 안됨
                    print('ERROR: Invalid syntax (Rd and Rn cannot same)')
                    sys.exit(1)
                
                mach_code |= registers[args[2]]                     # Rm 설정
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
                
            if args[3] != ',':
                print('ERROR: Invalid syntax')
                sys.exit(1)
                
            if args[4] in registers:
                if registers[args[4]] == 15:
                    print('ERROR: Invalid syntax (MUL cannot use r15(pc)')
                    sys.exit(1)
                    
                mach_code |= (registers[args[4]] << 8)              # Rs 설정
            
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
    
    elif(inst == 'mla'):
        mach_code |= (1 << 21)                                      # A = 1
        if(len(args) != 7):
            print('ERROR: Invalid syntax')
            sys.exit(1)
        
        if args[0] in registers:
            if registers[args[0]] == 15:
                print('ERROR: Invalid syntax (MLA cannot use r15(pc)')
                sys.exit(1)
            
            mach_code |= (registers[args[0]] << 16)                 # Rd
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)    
        
        if args[1] != ',':
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        if args[2] in registers:
            if registers[args[2]] == 15:                            
                print('ERROR: Invalid syntax (MLA cannot use r15(pc)')
                sys.exit(1)

            if registers[args[0]] == registers[args[2]]:            # Rd와 Rm 같으면 안됨
                print('ERROR: Invalid syntax (Rd and Rn cannot same)')
                sys.exit(1)
            mach_code |= (registers[args[2]])                       # Rm
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        if args[3] != ',':
            print('ERROR: Invalid syntax')
            sys.exit(1)

        if args[4] in registers:
            if registers[args[4]] == 15:
                print('ERROR: Invalid syntax (MLA cannot use r15(pc)')
                sys.exit(1)
                
            mach_code |= (registers[args[4]] << 8)                  # Rs
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)

        if args[5] != ',':
            print('ERROR: Invalid syntax')
            sys.exit(1)
    
        if args[6] in registers:
            if registers[args[6]] == 15:
                print('ERROR: Invalid syntax (MLA cannot use r15(pc)')
                sys.exit(1)
            mach_code |= (registers[args[6]] << 12)                 # Rn
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)
    
    return mach_code


# umull, smull 처리 함수
# Op{cond}{S} RdLo, RdHi, Rm, Rs     (UMULL, SMULL, UMLAL, SMLAL)
def mul_long_instruction(mach_code, tok, args):
    mach_code |= (1 << 23)
    mach_code |= (0b1001 << 4)
    inst = tok[:5]
    tok = tok[5:]
    
    if inst[0] == 's':              # signed면 U를 1로 세팅
        mach_code |= (1 << 22)
        
    if inst[1:4] == 'mla':
        mach_code |= (1 << 21)
        
    (mach_code, tok) = process_cond_field(mach_code, tok)
    (mach_code, tok) = process_S_flag(mach_code, tok)
    
    if args[0] in registers:                        
        if registers[args[0]] == 15:
            print('ERROR: Invalid syntax (you cannot use r15(pc))s')
            sys.exit(1)
            
        mach_code |= (registers[args[0]] << 12)             # RdLo
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if args[1] != ',':
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if args[2] in registers:
        if registers[args[2]] == 15:
            print('ERROR: Invalid syntax (you cannot use r15(pc))s')
            sys.exit(1)
            
        mach_code |= (registers[args[2]] << 16)             # RdHi
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if args[3] != ',':
        print('ERROR: Invalid syntax')
        sys.exit(1)
            
    if args[4] in registers:
        if registers[args[4]] == 15:
            print('ERROR: Invalid syntax (you cannot use r15(pc))s')
            sys.exit(1)
        mach_code |= registers[args[4]]                     # Rm
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if args[5] != ',':
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if args[6] in registers:
        if registers[args[6]] == 15:
            print('ERROR: Invalid syntax (you cannot use r15(pc))s')
            sys.exit(1)
        mach_code |= registers[args[6]] << 8                # Rs
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    return mach_code


# op{cond}{type} Rd, [Rn {, #offset}]        ; immediate offset
# op{cond}{type} Rd, [Rn, #offset]{!}          ; pre-indexed
# op{cond}{type} Rd, [Rn], #offset           ; post-indexed
def memory_instruction(mach_code, tok, args, pc):
    if re.match(str_format, tok):
        if tok[-1] == 'b':
            mach_code |= (0b1011100 << 20)
            
        else:
            mach_code |= (0b1011000 << 20)
            
    elif re.match(ldr_format, tok):
        if tok[-1] == 'b':
            mach_code |= (0b1011101 << 20)
            
        else:
            mach_code |= (0b1011001 << 20)
    inst = tok[:3]        
    tok = tok[4:6]
    
    (mach_code, tok) = process_cond_field(mach_code, tok)
    
    if args[0] in registers:
        mach_code |= (registers[args[0]] << 12)                 # Rd
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
    
    if args[1] != ',':
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    if args[2] == '[':
        if args[3] in registers:
            mach_code |= (registers[args[3]] << 16)         # Rn
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)
        
        if args[4] == ']':
            if len(args[5:]) == 0:
                return mach_code
            if args[5] == '!':
                mach_code |= (1 << 21)                      # W bit (!)
                if len(args[6:]) != 0:
                    print('ERROR: Invalid syntax')
                    sys.exit(1)
                return mach_code
            
            if args[5] != ',':
                print('ERROR: Invalid syntaxx')
                sys.exit(1)
            
            mach_code ^= (1 << 24)                          # pre -> post
            if args[6].startswith('#'):                     # imme post index
                rm = string_to_num(args[6])
                if rm < 0:
                    rm = -rm
                    mach_code ^= (1 << 23)                  # up -> down (U bit)
                if (rm & ~(0xfff)) != 0:
                    print('ERROR: offset is not 12 bit constant')
                    sys.exit(1)
                mach_code |= rm                             #(offset)
                if len(args[7:]) != 0:
                    print('ERROR: Invalid syntax (imme can not shift')
                    sys.exit(1)
                return mach_code
            
            if args[6].startswith('-'):                     # -Rm
                mach_code ^= (1 << 23)                      # up -> down (U bit)
                args[6] = args[6].lstrip('-')
            
            if args[6] in registers:
                mach_code |= registers[args[6]]             # offset
                args = args[7:]
                if len(args) == 0:
                    mach_code |= (1 << 25)                  # 레지스터면 I = 1
                    return mach_code
                
                if args[0] != ',':
                    print('ERROR: Invalid syntax (no comma)')
                    sys.exit(1)

                (mach_code, args) = process_shift(mach_code, args)
                mach_code |= (1 << 25)                      # 레지스터면 I = 1
                
                if len(args) != 0:
                    print('ERROR: Invalid syntax')
                    sys.exit(1)
            
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
            
        elif args[4] == ',':                                # pre index 처리
            if args[5].startswith('#'):                     # imme면 imme만 있어야함
                rm = string_to_num(args[5])
                if rm < 0:
                    rm = -rm
                    mach_code ^= (1 << 23)                  # up -> down (U bit)
                if (rm & ~(0xfff)) != 0:
                    print('ERROR: offset is not 12bit constant')
                    sys.exit(1)
                mach_code |= rm                             # offset
                if args[6] != ']':
                    print('ERROR: Invalid syntax (no \']\'')
                    sys.exit(1)
                if args[7] == '!':                          # ! 있으면 W bit 1로
                    mach_code |= (1 << 21)
                return mach_code
            
            if args[5].startswith('-'):                     # -Rm 가능
                mach_code ^= (1 << 23)                      # up -> down (U bit)
                args[5] = args[5].lstrip('-')
            if args[5] in registers:
                mach_code |= registers[args[5]]             # Rm
            if args[6] == ']':
                if args[7] == '!':
                    mach_code |= (1 << 21)                   # W bit (!)
                mach_code |= (1 << 25)                          # 레지스터면 I = 1로 만듦
                return mach_code
            
            elif args[6] == ',':                                # shift 처리
                args = args[6:]
                if args[2][0] != '#':                           # 시프트에 레지스터 사용 불가
                    print('ERROR: Invalid syntax (pre, post index only imme shift)')
                    sys.exit(1)
                (mach_code, args) = process_shift(mach_code, args)
                mach_code |= (1 << 25)                          # 레지스터면 I = 1로 만듦
                if args[0] != ']':
                    print('ERROR: Invalid syntax (no \']\'')
                    sys.exit(1)
                if len(args) > 1 and args[1] == '!':                              # W bit (!)
                    mach_code |= (1 << 21)
                return mach_code
            
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
    
    elif inst == 'ldr' and args[2] in text_symbol_table:           # symbol만 있는거 처리
        # 다른거 그대로 박고 주소만 pre에 [pc, #offset]으로 만듦
        # 만드는 방법은 symbol table에서 주소 가져오고 (pc + 8) 빼주면 됨
        mach_code |= (registers['pc'] << 16)        # Rn을 Pc로 설정
        offset = text_symbol_table[args[2]] - (pc + 8)      # offset을 심볼 주소에서 pc+8을 빼줌
        if offset < 0:                                      # 음수면 절대값 취하고
            offset = -offset
            mach_code ^= (1 << 23)                          # up -> down (U bit)
        if offset & ~(0xfff) != 0:
            print('ERROR: offset out of range')
            sys.exit(1)
        mach_code |= offset                                 # offset 입력
        return mach_code
    
    elif args[2] in data_symbol_table:              # data section 에 있으면 에러
        print('ERROR: Segmentation Fault')
        sys.exit(1)
    
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    return mach_code

# adr 명령어 처리 -> symbol이 text내에 있는지 확인하고 add로 바꿔서 변환
# condition 처리 필요 확인 필요 / ldr도 확인 필요
def adr_process(mach_code, tok, args, pc):
    cond = tok[3:]
    label = args[2]
    if label in text_symbol_table:
        offset = text_symbol_table[label] - (pc + 8)
        args[2] = 'pc'
        args.append(',')
        args.append('#' + str(offset))
        (mach_code, tok) = data_processing_instruction(mach_code, 'add' + cond, args)
        return mach_code
    elif label in data_symbol_table:
        print('ERROR: Segmentation Fault')
        sys.exit(1)
    else:
        print('ERROR: cant find symbol')
        sys.exit(1)
    
    

# b, bl 등 분기 명령어 처리
# addr = (pc + 8) + (offset * 4)
#B{cond} label
#BL{cond} label
def branch_process(mach_code, tok, args, pc):

    if re.match('b' + cond_regexp + '?', tok) and (len(tok) == 1 or len(tok) == 3):
        mach_code |= (0b1010 << 24)
        tok = tok[1:]
    elif re.match('bl' + cond_regexp + '?', tok) and (len(tok) == 2 or len(tok) == 4):
        mach_code |= (0b1011 << 24)
        tok = tok[2:]

    (mach_code, tok) = process_cond_field(mach_code, tok)
    
    if args[0] in text_symbol_table:
        offset = int((text_symbol_table[args[0]] - (pc + 8)) / 4)
        offset &= (0xffffff)                                        # 음수일수도 있으니 범위 제한
        mach_code |= offset
        return mach_code
    
    elif args[0] in data_symbol_table:
        print('ERROR: Segmentation fault')
        sys.exit(1)
    else:
        print('ERROR: can not find %s in symbol table'%args[0])
        sys.exit(1)
    
# bx 명령어 처리 함수 
def bx_process(mach_code, tok, args):
    mach_code |= (0x12fff1 << 4)
    tok = tok[3:]
    (mach_code, tok) = process_cond_field(mach_code, tok)
    
    if args[0] in registers:
        mach_code |= registers[args[0]]
    else:
        print('ERROR: Invalid syntax')
        sys.exit(1)
        
    return mach_code


# ldm/stm 과 mode를 받아서 처리하는 함수
# 같은 것끼리 묶어서 처리
def process_mode_field(mach_code, mode, inst):
    if inst == 'ldm':
        mach_code |= (1 << 20)
        if mode == 'fd' or mode == 'ia':
            mach_code |= (0b10001001 << 20)
            
        elif mode == 'fa' or mode == 'da':
            mach_code |= (0b10000001 << 20)
            
        elif mode == 'ed' or mode == 'ib':
            mach_code |= (0b10011001 << 20)
            
        elif mode == 'ea' or mode == 'db':
            mach_code |= (0b10010001 << 20)
            
        else:                                   # 기본값은 IA
            mach_code |= (0b10001001 << 20)
            
    elif inst == 'stm':
        if mode == 'fd' or mode == 'db':
            mach_code |= (0b10010000 << 20)
            
        elif mode == 'fa' or mode == 'ib':
            mach_code |= (0b10011000 << 20)
            
        elif mode == 'ed' or mode == 'da':
            mach_code |= (0b10000000 << 20)
            
        elif mode == 'ea' or mode == 'ia':
            mach_code |= (0b10001000 << 20)
            
        else:                                   # 기본값은 IA
            mach_code |= (0b10001000 << 20)
    
    elif inst == 'push':                        # push/pop은 rn이 13으로 고정
        mach_code |= (0b100100101101 << 16)
    elif inst == 'pop':
        mach_code |= (0b100010111101 << 16)
        
    return mach_code


# r1-r12 처럼 연속한 것 처리
def register_range_process(mach_code, begin, end):
    if begin in registers and end in registers: # 둘다 레지스터일 때
        begin = registers[begin]
        end = registers[end]
        if begin >= end:                        # 순서는 시작이 더 작아야함
            print('ERROR: bad range in register list')
            sys.exit(1)
        while begin <= end:                     # 시작을 하나씩 키우면서 1로 세팅
            if mach_code & (1 << begin) == 0:
                mach_code |= (1 << begin)
                begin += 1
            else:                               # 만약 이미 1로 세팅되어 있으면 중복이라 에러 출력
                print('ERROR: duplicate register')
                sys.exit(1)

        return mach_code
    else:
        print('ERROR: bad range in register list')
        sys.exit(1)

# LDM, STM, push, pop
# mode(FD, ED, FA, EA / IA, IB, DA, DB) 
# op{cond}mode Rn{!}, reglist{^}
def block_data_process(mach_code, tok, args):
    if re.match('push' + cond_regexp + '?', tok):       # push만 4글자
        inst = tok[:4]
        tok = tok[4:]
    else:                                               # 나머지 3글자 (pop, ldm, stm)
        inst = tok[:3]
        tok = tok[3:]
    
    (mach_code, tok) = process_cond_field(mach_code, tok)   # cond 처리
    mode = tok[:2]
    
    mach_code = process_mode_field(mach_code, mode, inst)   # mode , inst 처리
    
    splitter2 = re.compile(r'([ \t\n,\[\]\{\}\-!])')
    tokens = []
    for x in args:
        tokens.extend(splitter2.split(x))
    args = [tok for tok in tokens
              if re.match('\s*$', tok) == None]
    
    if inst == 'push' or inst == 'pop':                         # push, pop은 rn이 sp로 고정
        if args[0] != '{':
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        if args[1] in registers:
            if args[2] == '-':                                  # 범위 처리
                mach_code = register_range_process(mach_code, args[1], args[3])
                args = args[4:]
            else:
                mach_code |= (1 << registers[args[1]])          # 아니면 그냥 순서 맞춰서 비트 설정
                args = args[2:]   
        
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)
        
        while args[0] == ',':                               # 콤마가 나오는 동안 계속 반복
            if args[1] in registers:                        # 레지스터 확인
                if args[2] == '-':                          # 범위 처리
                    mach_code = register_range_process(mach_code, args[1], args[3])
                    args = args[4:]                         # 콤마나 중괄호 남기도록 자름
                else:
                    if mach_code & (1 << registers[args[1]]) == 0:
                        mach_code |= (1 << registers[args[1]])      # 단일 처리
                        args = args[2:]                             # 콤마나 중괄호 남기도록 자름
                    else:
                        print('ERROR: duplicate register')
                        sys.exit(1)
            
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
                
        if args[0] != '}':                                          # 중괄호 안나오면 에러
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        return mach_code
    
    elif inst == 'ldm' or inst == 'stm':
        if args[0] in registers:                                    # Rn
            base = registers[args[0]]
            if base == 15:
                print('ERROR: %s base register must not pc(r15)'%inst)
                sys.exit(1)
            mach_code |= (base << 16)
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        if args[1] == '!':                              # ! 있으면 W bit = 1
            mach_code |= (1 << 21)
            if args[2] != ',':
                print('ERROR: Invalid syntax (,)')
                sys.exit(1)
            args = args[3:]
            
        elif args[1] == ',':
            args = args[2:]
        
        else:
            print('ERROR: Invalid syntax (,)')
            sys.exit(1)

        if args[0] != '{':
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        if args[1] in registers:
            if args[2] == '-':                              # 레지스터 범위 처리
                mach_code = register_range_process(mach_code, args[1], args[3])
                args = args[4:]
            else:
                mach_code |= (1 << registers[args[1]])      # 단일 처리
                args = args[2:]   
        else:
            print('ERROR: Invalid syntax')
            sys.exit(1)
        
        while args[0] == ',':                               # 콤마인동안 반복
            if args[1] in registers:
                if args[2] == '-':                          # 밤위 처리
                    mach_code = register_range_process(mach_code, args[1], args[3])
                    args = args[4:]
                else:                                       # 단일 처리
                    if mach_code & (1 << registers[args[1]]) == 0:
                        mach_code |= (1 << registers[args[1]])
                        args = args[2:]
                    else:
                        print('ERROR: duplicate register')
                        sys.exit(1)
            else:
                print('ERROR: Invalid syntax')
                sys.exit(1)
                
        if args[0] != '}':                              # 중괄호 닫고 끝
            print('ERROR: Invalid syntax')
            sys.exit(1)
            
        return mach_code



#명령어 처리 함수(토큰 리스트 입력 받음)
def process_instruction(tokens, pc):
    
    mach_code = 0                   # 기계어 저장 변수
    tok = tokens[0].lower()                 # 맨 처음 나온 토큰이 명령어
    # print('token[0] =', tok)
    #args = tokens[1:]               # 그 뒤는 피연산자
    args = [x.lower() for x in tokens[1:]]               # 그 뒤는 피연산자
    print('args: ', args)
    if re.match(dp_format, tok):                                       #명령어가 정규식과 일치하면 
        print('\tData processing FAMILY')                                       
        (mach_code, tok) = data_processing_instruction(mach_code, tok, args)

    elif re.match(swi_format, tok):                                     # swi 
        print('\t SWI FAMILY')
        mach_code = swi_instruction(mach_code, tok, args)
        
    elif re.match(mul_format, tok):                                     # mul / mla
        print('\t MUL or MLA')
        mach_code = mul_instruction(mach_code, tok, args)
    
    elif re.match(mul_long_format, tok):                                # mul, mla
        print('\t MUL Long Family')
        mach_code = mul_long_instruction(mach_code, tok, args)
        
    elif re.match(ldr_format, tok) or re.match(str_format, tok):       # ldr, str
        print('\tMemory Instruction Family')
        mach_code = memory_instruction(mach_code, tok, args, pc)
        
    elif re.match(adr_format, tok):                                     # adr
        print('\tADR instruction')
        mach_code = adr_process(mach_code, tok, args, pc)
        
    elif re.match(bx_format, tok):                                      # bx
        print('\tBX instruction')
        mach_code = bx_process(mach_code, tok, args)
        
    elif re.match(branch_format, tok):                                  #b / bl
        print('\tBranch Family')
        mach_code = branch_process(mach_code, tok, args, pc)
                                                                        # ldm / stm / push / pop
    elif re.match(block_data_format, tok) or re.match('(push|pop)' + cond_regexp + '?', tok):
        print('\tBlock Data Process Family')
        mach_code = block_data_process(mach_code, tok, args)
        
        
    return mach_code




# 나중에 메인에서 불러 쓸 함수
def two_pass(lines, text_symbols, data_symbols):
    global text_symbol_table
    global data_symbol_table
    machine = {}
    text_symbol_table = text_symbols
    data_symbol_table = data_symbols
    for pc in lines.keys():
        tokens = lines[pc]
        mach_code = process_instruction(tokens, pc)
        machine[pc] = mach_code
    
    return machine
