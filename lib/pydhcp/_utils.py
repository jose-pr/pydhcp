import typing as _ty
import types as _types


class Missing:
    ...


MISSING = Missing()


T = _ty.TypeVar("T")
P = _ty.TypeVarTuple("P")

#P = _ty.ParamSpec("P")

if _ty.TYPE_CHECKING:
    class GenericMeta(type):
        ...
else:
    class GenericMeta(type):
        # https://stackoverflow.com/questions/60985221/how-can-i-access-t-from-a-generict-instance-early-in-its-lifecycle

        __concrete__ = {}
        def __getitem__(cls, key_t):
            cache = cls.__concrete__
            if c := cache.get(key_t, None):
                return c
            if not isinstance(key_t, tuple):
                key_t = (key_t,)
            name = f"{_ty._type_repr(cls)}[{", ".join([_ty._type_repr(a) for a in key_t])}]"
            cache[key_t] = c = _types.new_class(
                name, (cls,), {}, lambda ns: ns.update(_args_=key_t)
            )
            return c
