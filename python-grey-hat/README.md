# 《Python灰帽子——黑客与逆向工程师的Python编程之道》
# 《Gray Hat Python: Python Programming for Hackers and Reverse Engineers》

## 说明
1. 该目录是改书的学习记录，主要是书上代码的修复与移植，移植到以下环境：
    + Windows 10, 64-bit, x64
    + Intel(R) Core(TM) i7-4790 CPU
    + Python 3.6.5
2. 书上代码是32位操作系统，Python2.x，而且代码本身也有一些萌新难以发现的错（也有一些容易排除的），主要是前三章
3. 代码中有不少注释

## 参考资料
1. [GitHub, fork - CoiroTomas - GrayHatPython3-x64](https://github.com/LittleSec/GrayHatPython3-x64)
2. [<Gray Hat Python>书中纠错，以及每节的代码实现](https://github.com/inkydragon/GHP-PyDbg)
    + 这个repo里还提到了一些链接也值得参考，issue有非官方翻译版书的链接
3. [MSDN, 微软开发者网站](https://msdn.microsoft.com/zh-cn/)
4. [英文电子书](https://github.com/mehransab101/Grey-Hat-Python)
5. [CSDN, giantbranch - Python灰帽子--黑客与逆向工程师的Python编程之道 笔记，过程问题解决](https://blog.csdn.net/u012763794/article/details/52174275)

## 大体需要注意到的地方
1. 对于字符串，Python2是byte-string，而3就是Unicode-string，而in WinAPI all functions
    + ends with 'A' accept asci-strings
    + ends with 'W' accept unicode-strings
    + 所以部分函数，例如`CreateProcessA()`等传参为字符串时需要穿byte-string: `b"example"`
2. 32bit和64bit的代码会有不同，不同cpu架构也有所不同，尤其是涉及到寄存器。尤其是`my_debugger_defines.py`里的`CONTEXT()`结构体，里面记录了解msdn的文档链接。

## 学习建议
1. 书本为主，原书或者是两个中文翻译版都行，但是代码都是有问题的（即使环境和书的一样）
2. 代码最好自己敲，敲的时候可以参考这个repo的，也可以参考上面的资料，各有优劣
3. 有机会要接触一下msdn，搜搜对应的结构体和函数原型
4. 第三章真的值得看！虽然实际上不会自己去动手写，后面章节会介绍更好的库。

## TODO
1. 中断那一块原理还没完全弄懂，尤其是硬件中断。
