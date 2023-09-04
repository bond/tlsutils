def flatten_tuple(tuppp):
    """
    Flattens tuple to key/value pairs
    """
    for tup in tuppp:
        if isinstance(tup, tuple) and any(isinstance(sub, tuple) for sub in tup):
            for sub in flatten_tuple(tup):
                yield sub
        else:
            yield tup