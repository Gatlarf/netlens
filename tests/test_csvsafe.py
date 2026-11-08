from app import csvsafe


def test_formulas_are_defused_and_empty_cells_stay_empty():
    assert csvsafe.cell("=1+1") == "'=1+1" and csvsafe.cell("@SUM(A1)") == "'@SUM(A1)" and csvsafe.cell("-2") == "'-2" and csvsafe.cell("\tx") == "'\tx"
    assert csvsafe.cell("") == "" and csvsafe.cell("never") == "never" and csvsafe.cell(5) == 5 and csvsafe.cell(None) is None
