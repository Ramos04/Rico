─
│
┌
└
┤
┼
├
┬
└

# EXAMPLE OF OUTPUT WANTED
─ KEY : VALUE
┌ DICT
├─── KEY : VALUE
├──┬ KEY (DICT)
│  ├─── KEY : VALUE
│  ├─── KEY : VALUE
│  ├──┬ KEY (LIST)
│  │  ├─── ITEM 1
│  │  ├─── ITEM 2
│  │  ├─── ITEM 3
│  │  └──┬ ITEM 4 (DICT)
│  │     ├─── KEY : VALUE
│  │     ├─── KEY : VALUE
│  │     └─── KEY : VALUE
│  ├─── KEY : VALUE
│  ├─── KEY : VALUE
│  ├─── KEY : VALUE
│  └──┬ KEY (LIST)
│     ├─── ITEM 1
│     └─── ITEM 2
├─── KEY : VALUE
└─── KEY : VALUE
┌ LIST
├──┬ ITEM 1 (LIST)
│  ├─── KEY : VALUE
│  ├─── KEY : VALUE
│  ├──┬ KEY (DICT)
│  │  ├─── KEY : VALUE
│  │  ├─── KEY : VALUE
│  │  └─── KEY : VALUE
│  └─── KEY : VALUE
├── ITEM 2
└── ITEM 3

if the data is a dict:

    if this is the first item in the dict:

        if this is the first call to the function:
            print like this
            '┌ DICT'

        else:

    if this is the last item in the dict:

    else:

else:
    print like normal
    '─ KEY : VALUE'
