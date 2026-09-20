import typing as _ty
import types as _types

if _ty.TYPE_CHECKING:

    class GenericMeta(type): ...

else:

    class GenericMeta(type):
        # https://stackoverflow.com/questions/60985221/how-can-i-access-t-from-a-generict-instance-early-in-its-lifecycle

        def __getitem__(cls, key_t):
            # Normalise *before* the lookup. The key was normalised to a tuple
            # only on the miss path, so `List[X]` looked up `X` and stored
            # `(X,)` -- the lookup never matched what the store had written, and
            # every subscription built a fresh class. `List[X] is List[X]` was
            # False, which is the part that actually bites: two class objects
            # for one type make identity and issubclass checks unreliable.
            if not isinstance(key_t, tuple):
                key_t = (key_t,)

            # Per-class, not per-metaclass. `__concrete__` used to live on the
            # metaclass, so every generic class shared one namespace keyed only
            # by the type arguments: once the lookup worked, `Other[U8]` would
            # have been served `List[U8]`. That bug was invisible while the
            # cache never hit, and fixing the lookup alone would have exposed
            # it. `cls.__dict__` rather than `getattr` so a subscripted class
            # does not inherit and then write into its base's cache.
            cache = cls.__dict__.get("__concrete__")
            if cache is None:
                cache = {}
                setattr(cls, "__concrete__", cache)

            concrete = cache.get(key_t)
            if concrete is not None:
                return concrete

            args_repr = ", ".join(_ty._type_repr(a) for a in key_t)
            name = f"{_ty._type_repr(cls)}[{args_repr}]"
            cache[key_t] = concrete = _types.new_class(
                name, (cls,), {}, lambda ns: ns.update(_args_=key_t)
            )
            return concrete
