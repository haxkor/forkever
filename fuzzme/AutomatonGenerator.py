ALP_SIZE = 6
STATE_SIZE = 8

a = "a"
b = "b"
c = "c"
d = "d"
e = "e"
f = "f"
g = "g"
h = "h"
i = "i"
j = "j"
k = "k"


class State:

    def __init__(self, trans, nr:int):
        print(trans)
        self.trans = self.makeTrans(trans)
        self.id = nr

    def makeTrans(self, trans_arg):
        trans = [0] * ALP_SIZE

        for trans_packed in trans_arg:
            print(trans_packed)
            chars, targetstate = trans_packed
            for single_c in chars:
                trans[ord(single_c) - ord("a")] = targetstate

        return trans


def makeAutomaton(state_list):
    def make_trans_c(state:State):
        pref = "{ "
        for targetstate in state.trans:
            pref += "%d, " % targetstate
        return pref + "},"

    return "int trans[][%= {\n" % ALP_SIZE + "\n".join(make_trans_c(state) for state in state_list)[:-1] + "};"


trans = [1] * STATE_SIZE

trans[0] = [([a], 0)]
trans[1] = [([a, b, c], 2)]
trans[2] = [([a],1), ([d], 2), ([e], 3)]
trans[3] = [([b], 6), ([a], 4)]
trans[4] = [([b], 5)]
trans[5] = [([e], 6)]
trans[6] = [([c, d], 7)]
trans[7] = [([f], 8), ([a,b], 1)]

#result = makeAutomaton(State(transitem, i) for (i,transitem) in enumerate(trans))

#print(result)

def makeAutomatonLatex(state_list):

    # \node[state,initial] (q_0)   {$q_0$};
    res = "".join( "\\node[state] (q%d) {$q%d$};\n" % (state.id,state.id) for state in state_list)


    res += "\path[->]\n"

    def make_trans(state:State):
        pref = "(q%d) " % state.id
        for i,target in enumerate(state.trans):
            if target==0:
                continue
            if target==state.id:
                pref += "edge [loop above] node {%s} ()" % ( chr(ord(a) + i))
            else:
                pref += "edge node {%s} (q%d)" % ( chr(ord(a) + i), target)

            pref += "\n"

        return pref

    return res + "".join(make_trans(s) for s in state_list)

automaton = [ State(transitem, i) for (i,transitem) in enumerate(trans)]

result = makeAutomatonLatex(automaton)
print(result)





