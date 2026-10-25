the rules:
the rules are defined in the files: Cipher, KeyGenerator and RoundFunction. These serve as interfaces. They are lists of what each part must be able to do, without saying how.

The tools:
BitUtils, HbeaTables:
this are basic utensils (convert, mix, shuffle) and the fixes recipes (the tables)

the cooks:
Sha256KeyGenerator and DesRoundFunction:
each class does one job: step 1 is that one makes the key and one deoe sthe mixing insiee each shuffle.

the orchestrator:
AbstractBlockCipher and HbeaCipher:
runs the whole process: checks the message and cuts it up, does the 8 rounds and puts it together.

xorCipher: a much simpler way of scrambling, only there to show you can swap one chef for another.

the waiter:
securemessenger, main: talks to the user. doesn't care which chef is cooking.

error message:
InvalidMessageException
this is used when the message is bad (empty, too long, strange characters)
