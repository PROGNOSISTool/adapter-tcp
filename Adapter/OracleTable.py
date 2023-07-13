import uuid
from AbstractSymbol import AbstractOrderedPair
from ConcreteSymbol import ConcreteOrderedPair

from sqlalchemy import (
    String,
    JSON,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, mapped_column

Base = declarative_base()


class Mapping(Base):
    __tablename__ = "mapping"
    id = mapped_column(String, primary_key=True)
    abstract = mapped_column(JSON)
    concrete = mapped_column(JSON)

class OracleTable:
    def __init__(self, dbURL) -> None:
        engine = create_engine(dbURL, echo=False)
        self.session: Session = sessionmaker(bind=engine)()
        Base.metadata.create_all(engine)

    def add(self, abstract: AbstractOrderedPair, concrete: ConcreteOrderedPair) -> None:
        mapping = Mapping()
        mapping.id = str(uuid.uuid4())

        mapping.abstract = abstract.toJSON()
        mapping.concrete = concrete.toJSON()
        self.session.add(mapping)
        self.session.commit()
