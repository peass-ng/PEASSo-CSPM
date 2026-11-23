"""Render private Findings Reports as self-contained PDFs."""
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path
import re
import unicodedata

from markdown_it import MarkdownIt
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

PROJECT_NAME = "PEASS'o CSPM"
PROJECT_URL = "https://github.com/peass-ng/PEASSo-CSPM"
W, H = A4
M = 45
TW = W - 2*M
FLOOR = 55
SEV = ('critical', 'high', 'medium', 'low', 'info')
LABEL = {s:s.title() for s in SEV}
COLORS = dict(zip(SEV, map(HexColor, ['#A71E3D','#B84222','#8A5C04','#275E99','#5A6373'])))
FILL = dict(zip(SEV, map(HexColor, ['#B82046','#C04A29','#C58818','#376FA9','#7E8A9E'])))
PAPER = HexColor('#F7F9FB')
INK = HexColor('#111D2B')
SUB = HexColor('#46566B')
RULE = HexColor('#D6E1EA')
TEAL = HexColor('#056677')
NAVY = HexColor('#0A1728')
TINT = HexColor('#ECF3F8')
KIND = {'vulnerability':'Vulnerability', 'hardening':'Hardening', 'image_cves':'Image CVEs', 'leaks':'Detected leaks'}


_FONT_DIR = Path(__file__).with_name('pdf_fonts')
for _face, _file in (
    ('Text', 'SourceSans3-Regular.ttf'), ('TextBold', 'SourceSans3-Bold.ttf'),
    ('TextItalic', 'SourceSans3-It.ttf'), ('TextBoldItalic', 'SourceSans3-BoldIt.ttf'),
    ('Display', 'SourceSans3-Semibold.ttf'), ('Mono', 'SourceCodePro-Regular.ttf'),
):
    pdfmetrics.registerFont(TTFont(_face, str(_FONT_DIR / _file)))
pdfmetrics.registerFontFamily('Text', normal='Text', bold='TextBold',
                              italic='TextItalic', boldItalic='TextBoldItalic')

# No user-supplied markup can create a URL, attachment, or remote image fetch.
_md = MarkdownIt('commonmark', {'html': False}).disable('image')


def readable(value):
    text = unicodedata.normalize('NFC', str(value or ''))
    text = ''.join(ch for ch in text if ch in '\n\t' or unicodedata.category(ch) not in ('Cc', 'Cf', 'Cs'))
    return text.strip()


def inline(text):
    rendered = _md.renderInline(readable(text).replace('\n', ' '))
    rendered = re.sub(r'<a\b[^>]*>|</a>', '', rendered)
    return (rendered.replace('<strong>', '<b>').replace('</strong>', '</b>')
            .replace('<em>', '<i>').replace('</em>', '</i>')
            .replace('<code>', '<font name="Mono">').replace('</code>', '</font>'))


def P(value, width, size=10, leading=None, font='Text', color=INK, markup=False):
    style = ParagraphStyle('block', fontName=font, fontSize=size, leading=leading or size*1.27,
                           textColor=color, splitLongWords=1)
    content = value if markup else escape(readable(value))
    content = re.sub(r"PEASS(?:'|&#x27;|&#39;|&apos;)o CSPM",
                     f'<link href="{PROJECT_URL}">{escape(PROJECT_NAME)}</link>', content)
    block = Paragraph(content, style)
    return block, block.wrap(width, H)[1]


def asset_list(row):
    return list(dict.fromkeys(value for value in row.get('affected_assets', ()) if isinstance(value, str)))


def timestamp(value):
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc)
        if value:
            stamp = datetime.fromisoformat(str(value).replace('Z','+00:00'))
            return stamp.astimezone(timezone.utc) if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def stamp(value, fmt='%d %b %Y · %H:%M'):
    moment=timestamp(value)
    return moment.strftime(fmt) if moment else 'Unavailable'


def section_note(row, key):
    text=readable(row.get(key))
    if key=='description' and row.get('kind')=='image_cves' and row.get('special_details'):
        text='\n\n'.join(
            part for part in text.split('\n\n')
            if not all(line.lstrip().startswith(('- ', '* ')) and 'sha256:' in line
                       for line in part.splitlines() if line.strip())
            and not re.fullmatch(r'\s*(?:See the full breakdown for )?\d+ additional entries?(?: in (?:the )?detailed breakdown)?[.\s]*',part,re.I))
    return text


def render_findings_pdf(*, name, generated_at, summary, issues, scopes):
    """Produce one complete report, independently of the UI page and filters."""
    target = BytesIO()
    c = canvas.Canvas(target, pagesize=A4, pageCompression=1)
    c.setTitle('Cloud security findings report')
    c.setAuthor(PROJECT_NAME)
    c.setSubject('Assessment findings, scope and schedule')
    rows=[]
    for idx,issue in enumerate(sorted(issues,key=lambda row: (
            SEV.index(row['severity']) if row.get('severity') in SEV else len(SEV))),1):
        rows.append(dict(issue,slug=f'f{idx}',code=f'F-{idx:02}',
                        severity=issue.get('severity') if issue.get('severity') in SEV else 'info',
                        kind=issue.get('kind') or 'finding', services=issue.get('services') or []))
    counts=Counter(row['severity'] for row in rows)
    kinds=Counter(row['kind'] for row in rows)
    scope_count=sum(len(row.get('scopes') or ()) for row in scopes)
    release=f"{stamp(generated_at)} UTC" if timestamp(generated_at) else 'Unavailable'
    name=re.sub(r'\bcombined\b(?:\s*[·:–—-]\s*)?', '', readable(name), flags=re.I).strip() or 'Findings report'
    providers=', '.join(sorted({readable(scope.get('provider')) for scope in scopes} - {''}))
    def drawp(block,x,top):
        p,h=block
        p.drawOn(c,x,top-h)
        return top-h

    def plain(value,x,top,width=TW,**kwargs):
        return drawp(P(value,width,**kwargs),x,top)

    def text(value,x,y,size=9,font='Text',color=INK):
        c.setFillColor(color);c.setFont(font,size);c.drawString(x,y,str(value))

    def right(value,x,y,size=9,font='Text',color=INK):
        c.setFillColor(color);c.setFont(font,size);c.drawRightString(x,y,str(value))

    def rule(x1,y,x2,col=RULE):
        c.setLineWidth(.55); c.setStrokeColor(col); c.line(x1,y,x2,y)

    def rect(x,y,w,h,fill,stroke=None,r=0):
        c.setFillColor(fill); c.setStrokeColor(stroke or fill); c.setLineWidth(.6)
        c.roundRect(x,y,w,h,r,fill=1,stroke=int(stroke is not None))

    def tracked(value,x,y,size=8,spacing=1.4,color=TEAL):
        c.saveState()
        a=c.beginText(x,y);a.setFillColor(color);a.setCharSpace(spacing);a.setFont('TextBold',size);a.textOut(value);c.drawText(a)
        c.restoreState()

    def glyph(severity,x,y,col=None,sz=3):
        c.setFillColor(col or COLORS[severity]);c.setStrokeColor(col or COLORS[severity]);c.setLineWidth(.95)
        if severity in ('critical','high'):
            path=c.beginPath()
            pts=[(x,y+sz),(x+sz,y),(x,y-sz),(x-sz,y)] if severity=='critical' else [(x,y+sz),(x+sz,y-sz),(x-sz,y-sz)]
            path.moveTo(*pts[0])
            for point in pts[1:]:path.lineTo(*point)
            path.close();c.drawPath(path,fill=1,stroke=0)
        elif severity=='low':
            c.rect(x-sz,y-sz,sz*2,sz*2,fill=1,stroke=0)
        else:
            c.circle(x,y,sz,fill=int(severity!='info'),stroke=1)

    def link(dest,x,top,width,h):
        c.linkRect('',dest,(x,top-h,x+width,top),relative=0,thickness=0)

    def subhead(label,x,y):
        tracked(label.upper(),x,y,7.7,1,TEAL)
        return y-11

    def draw_cyber_cloud():
        # The silhouette and highlighted route are taken from the site's PEASS'o CSPM mark.
        rim=[(34,74),(28,66),(30,57),(38,51),(44,50),(47,41),(55,34),(66,31),(76,34),
             (82,41),(89,40),(97,46),(100,55),(99,65),(94,72),(86,75),(60,76)]
        route=[(28,66),(42,62),(54,52),(66,44),(76,34)]

        def polygon(points, close=True):
            path=c.beginPath()
            path.moveTo(*points[0])
            for point in points[1:]:
                path.lineTo(*point)
            if close:
                path.close()
            return path

        c.saveState()
        c.translate(W/2-64*5,918)
        c.scale(5,-5)
        c.setLineJoin(1)
        c.setLineCap(1)
        silhouette=polygon(rim)
        c.saveState()
        c.clipPath(silhouette,fill=0,stroke=0)
        c.linearGradient(50,28,75,82,[HexColor('#346A78'),HexColor('#1A404D'),HexColor('#0B1E32')],
                         positions=[0,.48,1],extend=True)
        for vertices,color in [
            ([(44,50),(55,34),(66,44),(54,52)],'#2F616B'),
            ([(55,34),(66,31),(76,34),(66,44)],'#3B7580'),
            ([(66,44),(76,34),(82,41),(79,51)],'#2F626E'),
            ([(79,51),(89,40),(97,46),(90,58)],'#245460'),
            ([(28,66),(42,62),(34,74)],'#204454'),
            ([(42,62),(54,52),(60,64),(60,76),(34,74)],'#24505A'),
            ([(54,52),(66,44),(79,51),(60,64)],'#2A5963'),
            ([(79,51),(90,58),(76,66),(60,64)],'#1C4352'),
            ([(60,76),(76,66),(94,72),(86,75)],'#163546'),
        ]:
            c.setFillColor(HexColor(color))
            c.drawPath(polygon(vertices),fill=1,stroke=0)
        c.restoreState()

        interior=[[(34,74),(42,62),(60,64),(60,76)],[(44,50),(54,52),(60,64),(76,66),(86,75)],
                  [(55,34),(66,44),(79,51),(82,41)],[(79,51),(90,58),(97,46)],
                  [(79,51),(76,66),(94,72)],[(90,58),(99,65)]]
        c.setStrokeColor(HexColor('#527E88'));c.setLineWidth(.18)
        for points in interior:
            c.drawPath(polygon(points,False),fill=0,stroke=1)
        c.setStrokeColor(HexColor('#98C9CD'));c.setLineWidth(.29)
        c.drawPath(silhouette,fill=0,stroke=1)

        c.setStrokeColor(HexColor('#744745'));c.setLineWidth(1.65)
        c.drawPath(polygon(route,False),fill=0,stroke=1)
        c.setStrokeColor(HexColor('#F2AB97'));c.setLineWidth(.58)
        c.drawPath(polygon(route,False),fill=0,stroke=1)
        for x,y in [(60,64),(76,66),(79,51),(90,58)]:
            c.setFillColor(HexColor('#A0C6CA'));c.circle(x,y,.48,fill=1,stroke=0)
        for i,(x,y) in enumerate(route):
            c.setFillColor(HexColor('#15283A'));c.setStrokeColor(HexColor('#F8B29C'))
            c.setLineWidth(.35)
            c.circle(x,y,1.04 if i in (0,len(route)-1) else .71,fill=1,stroke=1)
        c.setStrokeColor(HexColor('#AF6A61'));c.setLineWidth(.18);c.circle(*route[-1],2.6,fill=0,stroke=1)
        c.restoreState()

    def dark_cover():
        c.radialGradient(W/2,660,310,[HexColor('#102942'),HexColor('#0A1D32'),HexColor('#081321')],
                         positions=[0,.57,1],extend=True)
        draw_cyber_cloud()
        project_brand(M,785,10,white,1.2)
        right('FINDINGS REPORT',W-M,785,8,'Mono',HexColor('#A5D5E4'))
        c.saveState();p=c.beginPath();p.roundRect(M,218,TW,301,20);c.clipPath(p,stroke=0,fill=0)
        c.linearGradient(M,510,530,210,[HexColor('#223C57'),HexColor('#172A40'),HexColor('#111E33')],positions=[0,.46,1],extend=True)
        c.restoreState()
        c.setStrokeColor(HexColor('#689BAD'));c.setLineWidth(.75);c.roundRect(M,218,TW,301,20,fill=0,stroke=1)
        tracked('CLOUD ASSESSMENT',M+23,474,9,1.6,HexColor('#96E5E8'))
        plain('Cloud security\nfindings report'.replace('\n','<br/>'),M+23,449,TW-46,size=47,leading=49,font='Display',color=white,markup=True)
        plain(name,M+25,340,TW-50,size=17,leading=19,color=HexColor('#CFEDF5'))
        rule(M+24,273,W-M-24,HexColor('#57758C'))
        for j,(a,b) in enumerate([('PLATFORM',providers or 'Unavailable'),('ASSESSMENTS',str(len(scopes))),('ISSUES',str(len(rows)))]):
            x=M+25+j*148
            tracked(a,x,253,7.4,1,HexColor('#A8C9D8'))
            plain(b,x,247,138,size=12.5,leading=13.5,color=white,font='TextBold')
        text('Report Generated',M,153,9.5,'TextBold',HexColor('#8FDCE4'))
        text(release,M,132,11,'Text',white)
        rule(M,78,W-M,HexColor('#375466'))
        tracked('CONFIDENTIAL',M,53,7.5,1.1,HexColor('#AEC9D5'))

    def start(key,label,title=None,kicker=None,level=0):
        c.bookmarkPage(key)
        if label:
            c.addOutlineEntry(label,key,level=level)
        c.setFillColor(PAPER);c.rect(0,0,W,H,fill=1,stroke=0)
        c.setFillColor(NAVY);c.rect(0,H-8,W,8,fill=1,stroke=0)
        project_brand(M,H-32,8.3,TEAL)
        for caption,dest,n in [('Contents','contents',0),('Findings register','register',1)]:
            x=W-M-(145 if n==0 else 78)
            if key != dest:
                text(caption,x,H-32,8,'TextBold',TEAL);link(dest,x,H-22,65,15)
        rule(M,H-44,W-M)
        if title:
            tracked(kicker or 'FINDINGS REPORT',M,H-78,8,1.25)
            return plain(title,M,H-90,TW,size=30,leading=33,font='Display')-14

    def end(section):
        rule(M,36,W-M)
        text('Confidential',M,20,7.5,'Text',SUB)
        right(f'{section}   /   {c.getPageNumber():02}',W-M,20,7.5,'Mono',SUB)
        c.showPage()

    def external(x, y, width, height):
        c.linkURL(PROJECT_URL, (x, y, x+width, y+height), relative=0, thickness=0)


    def project_brand(x, y, size, color, spacing=0):
        if spacing:
            tracked(PROJECT_NAME,x,y,size,spacing,color)
        else:
            text(PROJECT_NAME,x,y,size,'TextBold',color)
        width=pdfmetrics.stringWidth(PROJECT_NAME,'TextBold',size)+spacing*(len(PROJECT_NAME)-1)
        external(x-2,y-4,width+4,size+8)


    def closing_page():
        c.bookmarkPage('thanks')
        c.addOutlineEntry('Thank you','thanks')
        c.radialGradient(W/2,660,310,[HexColor('#102942'),HexColor('#0A1D32'),HexColor('#081321')],
                         positions=[0,.57,1],extend=True)
        draw_cyber_cloud()
        project_brand(M,785,10,white,1.2)
        rect(M,225,TW,294,HexColor('#13283D'),HexColor('#4A7184'),20)
        tracked('CLOUD SECURITY',M+25,474,8,1.3,HexColor('#96E5E8'))
        text('Thank you for using',M+25,409,38,'Display',white)
        text(PROJECT_NAME,M+25,353,43,'Display',white)
        width=pdfmetrics.stringWidth(PROJECT_NAME,'Display',43)
        external(M+23,343,width+5,53)
        plain('Explore the project, browse the documentation, or share feedback on GitHub.',M+25,316,TW-50,
              size=13,color=HexColor('#C6D8E4'))
        rect(M+25,253,144,34,HexColor('#A6EBE7'),None,7)
        text('Visit GitHub',M+39,265,12,'TextBold',NAVY)
        external(M+25,253,144,34)
        url_label='github.com/peass-ng/PEASSo-CSPM'
        text(url_label,M+25,192,11,'TextBold',HexColor('#A6EBE7'))
        external(M+23,188,pdfmetrics.stringWidth(url_label,'TextBold',11)+5,18)
        rule(M,78,W-M,HexColor('#375466'))
        tracked('CONFIDENTIAL',M,53,7.5,1.1,HexColor('#AEC9D5'))
        right(f'{c.getPageNumber():02}',W-M,53,7.5,'Mono',HexColor('#AEC9D5'))
        c.showPage()


    def prose_blocks(value,width,size):
        blocks=[]
        for raw in str(value or '').splitlines():
            line=raw.strip()
            if not line:
                continue
            line=re.sub(r'^#{1,6}\s+', '', line)
            prefix=''
            if line.startswith(('- ','* ')):
                prefix='• ';line=line[2:]
            blocks.append(P(prefix+inline(line),width,size,markup=True))
        return blocks

    def build_evidence(row):
        sections=[]
        risk=row.get('severity_evidence')
        if risk:
            items=[]
            for field,label in [('asset','Supporting asset'),('consequence','Consequence'),('prerequisites','Prerequisites'),('impact_level','Impact level'),('prerequisites_supported','Prerequisites supported'),('internet_reachable','Internet reachability')]:
                if field in risk:items.append((label,str(risk[field]).title() if isinstance(risk[field],bool) else str(risk[field]),None))
            sections.append(('Severity evidence',items))
        facts=row.get('source_facts') or {}
        if facts:
            items=[]
            if facts.get('retention_benchmark'):items.append(('Retention benchmark','Observed expiry settings were compared with the scanner benchmark.',None))
            if facts.get('short_retention_days'):items.append(('Observed retention',', '.join(map(str,facts['short_retention_days']))+' days',None))
            if facts.get('writable_task_definitions'):items.append(('Writable task definitions',f"{len(facts['writable_task_definitions'])} recorded definitions",None))
            if items:sections.append(('Captured facts',items))
        perms=row.get('permission_recommendations') or []
        if perms:
            items=[]
            for p in perms:
                meta=' · '.join(f"{k.replace('_',' ').title()} {p[k]}" for k in ('principal','provider','scope','kind','policy','source','confidence','usage_window_end','last_accessed','last_refreshed','replacement') if p.get(k))
                items.append((p.get('value','Permission change'),meta,None))
            sections.append(('Permission recommendations',items))
        special=row.get('special_details') or []
        if special:
            items=[]
            for s in special:
                label=s.get('asset') or s.get('label') or 'Captured evidence'
                if isinstance(label,list):label=', '.join(map(str,label))
                pieces=[s[k] for k in ('scope','digest') if s.get(k) and (k!='digest' or s[k] not in str(label))]
                if s.get('counts'):pieces.append(', '.join(f'{key.title()} {n}' for key,n in s['counts'].items()))
                items.append((label,' · '.join(map(str,pieces)),None))
            sections.append(('Image advisory evidence' if row['kind']=='image_cves' else 'Captured evidence',items))
        return sections

    def finding_header(row, continuation, draw=False):
        top=H-70
        tag=f"{row['code']}  /  {KIND.get(row['kind'],row['kind']).upper()}"
        if continuation:
            if draw:
                tracked(tag+'  /  CONTINUED',M,top-4,8,1.05,TEAL)
                rule(M,top-15,W-M)
            return top-30

        bwidth=90
        severity=row['severity']
        solid=severity in ('high','critical')
        title=P(row['title'],TW,23,leading=25,font='Display')
        y=top-22-title[1]-9
        if draw:
            tracked(tag,M,top-4,8,1.05,TEAL)
            rect(W-M-bwidth,top-13,bwidth,19,FILL[severity] if solid else TINT,None if solid else RULE,5)
            glyph(severity,W-M-bwidth+12,top-3,white if solid else COLORS[severity],3)
            text(LABEL[severity],W-M-bwidth+22,top-6,9.1,'TextBold',white if solid else COLORS[severity])
            drawp(title,M,top-22)
        assets=asset_list(row)
        status='Confirmed' if row['status']=='confirmed' else str(row['status']).replace('_',' ').capitalize()
        meta=P(f"{status}  ·  {len(assets):,} affected assets in this report",TW,9.1,color=SUB,font='TextBold')
        if draw:drawp(meta,M,y)
        y-=meta[1]+5
        if row['services']:
            services=P('Services  '+', '.join(row['services']),TW,8.6,leading=11,color=SUB)
            if draw:drawp(services,M,y)
            y-=services[1]+4
        if draw:rule(M,y,W-M)
        return y-15

    FINDING_BODY_PT = 11
    FINDING_SUPPORT_PT = 9.5
    FINDING_HEADING_PT = 9.2
    FINDING_HEADING_HEIGHT = 18
    FINDING_SECTION_GAP = 16

    def finding_sections(row):
        sections=[]
        for key,label in [('description','Observed Issue'),('impact','Impact'),
                          ('recommendation','Remediation'),('verification','Verification')]:
            value=section_note(row,key)
            blocks=prose_blocks(value,TW,FINDING_BODY_PT)
            if blocks:
                sections.append((label,[(p,False,4) for p in blocks]))
        assets=asset_list(row)
        shown=assets if len(assets)<=25 else assets[:10]
        items=[(P(asset,TW-14,FINDING_SUPPORT_PT,leading=12.2,font='Mono'),True,2) for asset in shown]
        if not shown:
            items.append((P('No directly affected assets were identified in the available evidence.',TW,FINDING_SUPPORT_PT,color=SUB),False,2))
        if len(assets)>25:
            items.append((P(f'{len(assets)-len(shown):,} additional affected assets.',TW,FINDING_SUPPORT_PT,font='TextBold',color=SUB),False,2))
        affected_scopes=[readable(scope) for scope in row.get('affected_scopes', ()) if isinstance(scope,str)]
        if row.get('affected_scope_incomplete'):
            items.append((P('Affected scope is incomplete in the captured evidence.',TW,FINDING_SUPPORT_PT,color=SUB),False,2))
        sections.append(('Affected assets',items))
        if affected_scopes:
            sections.append(('Affected scopes',[(P(scope,TW-14,FINDING_SUPPORT_PT,font='Mono'),True,2)
                                                 for scope in affected_scopes]))
        evidence={label:items for label,items in build_evidence(row) if items}
        for name in ('Severity evidence','Captured facts','Permission recommendations',
                     'Image advisory evidence','Captured evidence'):
            if name not in evidence:continue
            items=[]
            for title,value,_ in evidence[name]:
                markup=f'<b>{escape(str(title))}</b> · {escape(str(value))}' if value else f'<b>{escape(str(title))}</b>'
                items.append((P(markup,TW-14,FINDING_SUPPORT_PT,leading=12.2,markup=True,color=SUB),True,3))
            sections.append((name,items))
        return sections

    def pack_finding(row):
        pages=[[]]
        y=finding_header(row,False)
        for heading,items in finding_sections(row):
            queue=deque(items)
            needs_heading=True
            continued=False
            while queue:
                block,bullet,spacing=queue.popleft()
                head=FINDING_HEADING_HEIGHT if needs_heading else 0
                # Move the last asset and its count note together.
                note=(queue[0][0][1]+queue[0][2] if heading=='Affected assets'
                      and bullet and len(queue)==1 and not queue[0][1] else 0)
                if y-block[1]-spacing-head-note<FLOOR:
                    width=TW-14 if bullet else TW
                    starts_page=not pages[-1]
                    # A single very long paragraph must flow regardless of its size.
                    continuation_top = finding_header(row, True)
                    if block[1]+spacing+FINDING_HEADING_HEIGHT > continuation_top-FLOOR or starts_page:
                        fragments=block[0].split(width,y-FLOOR-head-spacing)
                        if len(fragments)>1 or fragments and starts_page:
                            measured=[(part,part.wrap(width,H)[1]) for part in fragments]
                            block,*remaining=measured
                            queue.extendleft(reversed([(part,False,spacing) for part in remaining]))
                            if len(fragments)>1:
                                queue.appendleft(None)
                        else:
                            if starts_page and y == continuation_top:
                                raise ValueError('A finding paragraph could not be paginated')
                            queue.appendleft((block,bullet,spacing))
                            if not starts_page:
                                pages.append([])
                            y=continuation_top
                            needs_heading=True
                            continue
                    else:
                        queue.appendleft((block,bullet,spacing))
                        pages.append([])
                        y=continuation_top
                        needs_heading=True
                        continue
                if needs_heading:
                    pages[-1].append(('heading',heading+(' (continued)' if continued else ''),FINDING_HEADING_HEIGHT))
                    y-=FINDING_HEADING_HEIGHT
                    needs_heading=False
                height=block[1]+spacing
                pages[-1].append(('block',(block,bullet),height))
                y-=height
                continued=True
                if queue and queue[0] is None:
                    queue.popleft()
                    pages.append([])
                    y=finding_header(row,True)
                    needs_heading=True
            pages[-1].append(('gap',None,FINDING_SECTION_GAP))
            y-=FINDING_SECTION_GAP
        return pages



    def paginate(entries, first, later):
        pages=[[]]
        available=first
        for entry in entries:
            height=entry[-1]
            if pages[-1] and height>available:
                pages.append([])
                available=later
            if height>available:
                raise ValueError('An export row is too tall for the report page')
            pages[-1].append(entry)
            available-=height
        return pages

    index_width=(TW-24)/2
    index_rows=[]
    for row in rows:
        label=P(row['title'],index_width-62,9,leading=11)
        index_rows.append((row,label,max(21,label[1]+8)))
    if sum(entry[-1] for entry in index_rows)<=840:
        # Balance two columns for ordinary reports.
        goal=sum(entry[-1] for entry in index_rows)/2
        cut=1 if index_rows else 0
        while cut<len(index_rows) and sum(entry[-1] for entry in index_rows[:cut])<goal:
            cut+=1
        index_columns=[index_rows[:cut],index_rows[cut:]]
    else:
        index_columns=paginate(index_rows,460,460)
    index_pages=[index_columns[i:i+2] for i in range(0,len(index_columns),2)]

    scope_rows=[]
    for scope in sorted(scopes,key=lambda s: timestamp(s.get('started')) or datetime.max.replace(tzinfo=timezone.utc)):
        identity=P(scope.get('name') or 'Assessment',TW-239,10.5,leading=13,font='TextBold')
        region_text=', '.join(str(item) for item in scope.get('scopes', ()))
        scope_details=P(f"{scope.get('provider') or 'Cloud'} · {region_text}" if region_text else scope.get('provider') or 'Cloud',
                        TW-239,8.8,leading=10.8,color=SUB)
        scope_rows.append((scope,identity,scope_details,max(35,identity[1]+scope_details[1]+13)))
    scope_pages=paginate(scope_rows,380,530)

    summary=re.sub(r'^Consolidated \d+ issues from .*?\.\s*','',readable(summary),count=1)
    summary=re.sub(r'References retain the source report for each observation; similarly named resources in different accounts are not treated as the same asset\.',
                   'Asset counts distinguish similarly named resources across accounts.',summary)
    summary_block=P(inline(summary),TW,10.6,leading=14,markup=True,color=SUB)
    overview_intro=[]
    if summary_block[1]>145:
        pending=summary_block
        while pending[1]>590:
            chunks=pending[0].split(TW,590)
            if len(chunks)!=2:
                raise ValueError('The report summary could not be paginated')
            overview_intro.append((chunks[0],chunks[0].wrap(TW,H)[1]))
            pending=(chunks[1],chunks[1].wrap(TW,H)[1])
        overview_intro.append(pending)

    register=[]
    for row in rows:
        title=P(row['title'],219,9,leading=11.3,font='TextBold')
        services=row.get('services') or ()
        label=' · '.join(services[:2]) + (f" +{len(services)-2}" if len(services)>2 else '')
        service=P(label or 'Unavailable',84,8.4,leading=10.2,color=SUB)
        register.append((row,title,service,max(title[1],service[1],10)+9))
    register_pages=paginate(register,590,590)

    plans={row['slug']:pack_finding(row) for row in rows}
    scope_start=2+len(index_pages)
    overview_start=scope_start+len(scope_pages)
    register_start=overview_start+len(overview_intro)+1
    report_pages={}
    next_page=register_start+len(register_pages)
    for row in rows:
        report_pages[row['slug']]=next_page
        next_page+=len(plans[row['slug']])

    c.bookmarkPage('cover')
    c.addOutlineEntry('Cover','cover')
    dark_cover()
    c.showPage()

    for index,columns in enumerate(index_pages):
        y=start('contents' if not index else f'contents-{index}',
                'Contents' if not index else None,'Contents','REPORT INDEX')
        if not index:
            y=plain('Read the assessment scope, compare findings, or jump to a finding.',M,y-1,TW,size=10.3,color=SUB)-28
            for key,label,page in [
                ('scope','Scope and schedule',scope_start),('overview','Findings at a glance',overview_start),
                ('register','Findings register',register_start),('thanks','Thank you',next_page),
            ]:
                text(label,M,y,11,'TextBold')
                right(f'{page:02}',W-M,y,9,'Mono',TEAL)
                rule(M,y-8,W-M)
                link(key,M,y+11,TW,19)
                y-=26
        y=subhead('Findings',M,y-5)-7
        for column,entries in enumerate(columns):
            x=M+column*(index_width+24)
            line_y=y
            for row,label,h in entries:
                glyph(row['severity'],x+3,line_y-6,sz=2.7)
                text(row['code'],x+11,line_y-8,7.7,'Mono',SUB)
                drawp(label,x+46,line_y+1)
                right(f"{report_pages[row['slug']]:02}",x+index_width,line_y-8,8,'Mono',TEAL)
                rule(x,line_y-h+3,x+index_width)
                link(row['slug'],x,line_y+2,index_width,h)
                line_y-=h
            assert line_y>FLOOR
        end('Contents')

    for index,entries in enumerate(scope_pages):
        y=start('scope' if not index else f'scope-{index}',
                'Scope and schedule' if not index else None,'Scope and schedule','ASSESSMENT CONTEXT')
        if not index:
            cw=(TW-18)/3
            for i,(value,label) in enumerate([(len(scopes),'Assessments'),(scope_count,'Recorded scope entries'),
                                              (len({s['provider'] for s in scopes if s.get('provider')}),'Cloud providers')]):
                x=M+i*(cw+9)
                rect(x,y-71,cw,71,TINT,RULE,8)
                text(value,x+13,y-35,25,'Display',TEAL)
                text(label,x+13,y-56,9,'Text',SUB)
            y-=96
        y=subhead('Assessment timeline · UTC',M,y)-8
        for label,x in [('ASSESSMENT / SCOPES',M),('LAUNCHED',M+280),('COMPLETED',M+398)]:
            tracked(label,x,y,7.4,.65,SUB)
        rule(M,y-8,W-M)
        y-=21
        for row,identity,regions,height in entries:
            end_name=drawp(identity,M,y+2)
            drawp(regions,M,end_name-1)
            text(stamp(row.get('started'),'%d %b · %H:%M'),M+280,y-8,9,'Text',SUB)
            text(stamp(row.get('completed'),'%d %b · %H:%M'),M+398,y-8,9,'Text',SUB)
            y-=height
            rule(M,y+4,W-M)
        if not entries:
            y=plain('Assessment schedule data is unavailable.',M,y,TW,color=SUB)-13
        if index==len(scope_pages)-1:
            y-=8
            rect(M,y-48,TW,48,TINT,RULE,7)
            text('Report Generated',M+12,y-17,10,'TextBold',TEAL)
            text(release,M+12,y-34,12,'TextBold')
            y-=66
            y=plain('This report describes captured assessment evidence. Assets and scopes reflect what the available evidence identifies.',
                    M,y,TW,size=9.4,color=SUB)-5
        assert y>FLOOR
        end('Scope')

    for index,block in enumerate(overview_intro):
        y=start('overview' if not index else f'overview-{index}', 'Findings at a glance' if not index else None,
                'Findings at a glance','EXECUTIVE OVERVIEW')
        drawp(block,M,y)
        end('Overview')

    y=start('overview-charts' if overview_intro else 'overview',None if overview_intro else 'Findings at a glance',
            'Findings at a glance','EXECUTIVE OVERVIEW')
    if not overview_intro and summary:
        y=drawp(summary_block,M,y)-18
    cw=(TW-18)/3
    for i,(value,label) in enumerate([(len(rows),'Issues'),(kinds['vulnerability'],'Vulnerabilities'),
                                       (counts['critical']+counts['high'],'High or Critical issues')]):
        x=M+i*(cw+9)
        rect(x,y-68,cw,68,TINT,RULE,8)
        text(value,x+13,y-33,26,'Display',TEAL)
        text(label,x+13,y-52,9,'Text',SUB)
    y=subhead('Severity distribution',M,y-91)-8
    if rows:
        pos=M
        for severity in SEV:
            width=TW*counts[severity]/len(rows)
            c.setFillColor(FILL[severity])
            c.rect(pos,y-13,width,13,stroke=0,fill=1)
            pos+=width
    y-=30
    for i,severity in enumerate(SEV):
        x=M+i*TW/5
        glyph(severity,x+4,y+3)
        text(f"{LABEL[severity]}  {counts[severity]}",x+13,y,9,'TextBold',COLORS[severity])
    y=subhead('Issues by service',M,y-32)-5
    y=plain('An issue can appear under several services.',M,y,TW,size=9,color=SUB)-13
    services=defaultdict(Counter)
    for row in rows:
        for service in row.get('services') or ():
            services[service][row['severity']]+=1
    ranked=sorted(services.items(),key=lambda item:(-sum(item[1].values()),item[0]))[:10]
    maximum=max((sum(bucket.values()) for _,bucket in ranked),default=1)
    if not ranked:
        plain('Service attribution is unavailable for these issues.',M,y,TW,size=9,color=SUB)
    for service,bucket in ranked:
        plain(service,M,y+8,127,size=8.7,leading=9,font='TextBold')
        pos=M+140
        span=TW-174
        c.setFillColor(TINT)
        c.rect(pos,y-1,span,8,fill=1,stroke=0)
        for severity in SEV:
            width=span*bucket[severity]/maximum
            if width:
                c.setFillColor(FILL[severity])
                c.rect(pos,y-1,width,8,fill=1,stroke=0)
                pos+=width
        right(sum(bucket.values()),W-M,y,8.6,'Mono',SUB)
        y-=18
    assert y>FLOOR
    end('Overview')

    for index,entries in enumerate(register_pages):
        y=start('register' if not index else f'register-{index}','Findings register' if not index else None,
                'Findings register','EXECUTIVE REGISTER')
        y=plain('Severity, services, and affected-asset counts.',M,y,TW,size=9.5,color=SUB)-15
        for label,offset in [('ID',0),('SEVERITY',45),('FINDING',109),('SERVICES',337),('ASSETS',428),('PAGE',473)]:
            tracked(label,M+offset,y,7.5,.55,SUB)
        rule(M,y-7,W-M)
        y-=11
        for row,title,service,h in entries:
            c.setFillColor(FILL[row['severity']])
            c.rect(M,y-h+4,1.6,h-7,fill=1,stroke=0)
            text(row['code'],M+7,y-10,8,'Mono',SUB)
            glyph(row['severity'],M+47,y-7,sz=2.6)
            text(LABEL[row['severity']],M+55,y-10,8.5,'TextBold',COLORS[row['severity']])
            drawp(title,M+109,y-2)
            drawp(service,M+337,y-2)
            right(f"{len(asset_list(row)):,}",M+452,y-10,8.4,'Mono',INK)
            right(f"{report_pages[row['slug']]:02}",W-M,y-10,8.4,'Mono',TEAL)
            rule(M,y-h,W-M)
            link(row['slug'],M,y,TW,h)
            y-=h
        if not entries:
            plain('No findings were recorded in this report.',M,y-4,TW,color=SUB)
        assert y>FLOOR
        end('Register')

    for row in rows:
        assert c.getPageNumber()==report_pages[row['slug']]
        for part,entries in enumerate(plans[row['slug']]):
            start(row['slug'] if not part else f"{row['slug']}-{part}",
                  row['code']+' '+row['title'] if not part else None)
            y=finding_header(row,bool(part),draw=True)
            for kind,content,height in entries:
                if kind=='heading':
                    tracked(content.upper(),M,y-8,FINDING_HEADING_PT,.75,TEAL)
                elif kind=='block':
                    block,bullet=content
                    if bullet:
                        c.setFillColor(TEAL)
                        c.circle(M+3,y-5,1.5,fill=1,stroke=0)
                    drawp(block,M+14 if bullet else M,y)
                y-=height
            assert y>=FLOOR-FINDING_SECTION_GAP,(row['code'],part,y)
            end(row['code']+(f"  /  {part+1} of {len(plans[row['slug']])}" if len(plans[row['slug']])>1 else ''))

    closing_page()
    c.save()
    return target.getvalue()
