# NSIS Bzip2 Decompressor

## Decompress Whole Data

```python
import nsisunbz2.core

bzd = nsisunbz2.core.Bz2Decompress(compressed)
decompressed = bzd.decompress()
```

## Stop Decompression Beyond Given Output Size

This is used when decompressing an NSIS script from a solid mode installer to save time.
The additional value is the size of the expected NSIS installer script. Exmple size shown
here is arbitrary.

```python
import nsisunbz2.core

bzd = nsisunbz2.core.Bz2Decompress(compressed)
decompressed = bzd.decompress(4687)
```
