from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ScanResult:
    """
    Représente le résultat du scan d'un port TCP.
    """

    port: int
    is_open: bool
    service: str
    banner: str | None = None

    @property
    def status(self) -> str:
        """
        Retourne l'état du port sous forme lisible.
        """
        return "open" if self.is_open else "closed"

    def to_dict(self) -> dict[str, object]:
        """
        Convertit le résultat en dictionnaire sérialisable.
        """
        data = asdict(self)
        data["status"] = self.status
        data.pop("is_open")

        return data
