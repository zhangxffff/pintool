import angr

b = angr.Project('a.out')

p = b.factory.path()

p.step()
while len(p.successors) != 0:
    print hex(p.addr), len(p.successors)
    p = p.successors[0]
    p.step()
