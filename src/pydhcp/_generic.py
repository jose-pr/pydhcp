from __future__ import annotations

import copyreg as _copyreg
import typing as _ty
import types as _types

if _ty.TYPE_CHECKING:

    class GenericMeta(type): ...

else:

    def _type_name(arg: _ty.Any) -> str:
        """A type argument as a reader writes it: `U8`, not its module path."""
        return arg.__name__ if isinstance(arg, type) else repr(arg)

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

            # Per-class, not per-metaclass. `_subscriptions` used to live on the
            # metaclass, so every generic class shared one namespace keyed only
            # by the type arguments: once the lookup worked, `Other[U8]` would
            # have been served `List[U8]`. That bug was invisible while the
            # cache never hit, and fixing the lookup alone would have exposed
            # it. `cls.__dict__` rather than `getattr` so a subscripted class
            # does not inherit and then write into its base's cache.
            cache = cls.__dict__.get("_subscriptions")
            if cache is None:
                cache = {}
                setattr(cls, "_subscriptions", cache)

            concrete = cache.get(key_t)
            if concrete is not None:
                return concrete

            name = f"{cls.__name__}[{', '.join(_type_name(a) for a in key_t)}]"
            cache[key_t] = concrete = _types.new_class(
                name,
                (cls,),
                {},
                lambda ns: ns.update(
                    _args_=key_t,
                    _origin_=cls,
                    __module__=cls.__module__,
                    __qualname__=name,
                ),
            )
            return concrete

    def _subscribe(origin: _ty.Any, args: tuple[_ty.Any, ...]) -> _ty.Any:
        return origin[args]

    def _reduce_class(cls: GenericMeta) -> _ty.Any:
        """Pickle a subscripted class as the subscription that builds it.

        Its name (`List[U8]`) is not an attribute of any module, so a pickle by
        name could not find it again, in this process or in another. Every other
        class of this metaclass is pickled by name as usual.
        """
        if "_origin_" in cls.__dict__:
            return _subscribe, (cls.__dict__["_origin_"], cls.__dict__["_args_"])
        return cls.__qualname__

    _copyreg.pickle(GenericMeta, _reduce_class)
