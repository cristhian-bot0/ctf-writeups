"""Reconstrucción del fuente original (judge_src.py) a partir del bytecode de
cinderbound.mpy. Los nombres de locales no están en el .mpy (sólo `syllable`,
que es argumento); el resto son inventados a partir de su uso.
"""


def judge(syllable):
    target = (57, 129, 154, 31, 199, 192, 73, 243, 43, 176, 255, 173, 54, 203, 67, 15)
    key = 90
    out = []
    i = 0
    while i < len(syllable):
        out.append(ord(syllable[i]) ^ key ^ ((i * 13) & 255))
        key = (key + ord(syllable[i])) & 255
        i += 1
    return out == list(target)
