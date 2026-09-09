import re,sys,os

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


def params_of(sig):
    # sig: text inside fn ( ... ) at top level
    depth=0; cur=''; out=[]
    for ch in sig:
        if ch in '(<[{': depth+=1
        if ch in ')>]}': depth-=1
        if ch==',' and depth==0:
            out.append(cur); cur=''
        else:
            cur+=ch
    if cur.strip(): out.append(cur)
    return out

def scan(path):
    src=open(path,encoding='utf-8').read()
    lines=src.split('\n')
    problems=[]
    i=0
    while i<len(lines):
        m=re.search(r'\bfn\s+([a-z_0-9]+)\s*(<[^>]*>)?\s*\(', lines[i])
        if not m:
            i+=1; continue
        # collect signature until balanced parens
        start=i
        text=lines[i][m.end()-1:]
        depth=0; sig=''
        j=i; k=m.end()-1
        done=False
        while j<len(lines) and not done:
            row=lines[j] if j>i else lines[i][m.end()-1:]
            for ch in row:
                if ch=='(':
                    depth+=1
                    if depth==1: continue
                elif ch==')':
                    depth-=1
                    if depth==0: done=True; break
                if depth>=1: sig+=ch
            if not done: sig+='\n'
            j+=1
        # body: from j to matching brace
        body=[]
        depth=0; started=False
        jj=j-1
        while jj<len(lines):
            for ch in lines[jj]:
                if ch=='{': depth+=1; started=True
                elif ch=='}': depth-=1
            body.append(lines[jj])
            if started and depth<=0: break
            jj+=1
        bodytext='\n'.join(body)
        # Объявление без тела — это трейт, а не функция: проверять в нём
        # нечего, и «параметр не использован» там всегда истинно и всегда
        # бессмысленно. Ловилось на `Store::export_into` и `stored_chunks`.
        #
        # Признак — что раньше встретится после подписи: точка с запятой
        # (объявление) или фигурная скобка (тело). Проверять просто наличие
        # `{` нельзя: сбор тела не останавливается на объявлении и дочитывает
        # до скобок **следующей** функции.
        opens=bodytext.find('{'); ends=bodytext.find(';')
        if ends!=-1 and (opens==-1 or ends<opens):
            i=j
            continue
        for p in params_of(sig):
            p=p.strip()
            if not p or p.startswith('&self') or p=='self' or p.startswith('mut self') or p.startswith('#['): continue
            name=p.split(':')[0].strip().replace('mut ','')
            if not re.match(r'^[a-z_][a-z_0-9]*$', name) or name.startswith('_'): continue
            if not re.search(r'\b'+re.escape(name)+r'\b', bodytext.split('{',1)[1] if '{' in bodytext else bodytext):
                problems.append((path, start+1, m.group(1), name))
        i=j
    return problems

# Без аргументов метелка смотрит **всё дерево**, а не молчит.
#
# Раньше пустой список означал «проверено ноль файлов», и печаталось
# бодрое «чисто». Метелка, зеленеющая от того, что её позвали без
# аргументов, хуже отсутствующей: она создаёт уверенность на пустом месте.
paths = sys.argv[1:]
if not paths:
    import glob as _glob
    paths = sorted(_glob.glob(str(ROOT_DIR / 'crates/*/src/**/*.rs'), recursive=True))

any_found=False
print('файлов проверено: %d' % len(paths))
for path in paths:
    for p in scan(path):
        any_found=True
        print('UNUSED %s:%d fn %s param %s' % p)
print('чисто' if not any_found else 'есть находки')
